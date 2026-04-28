package basicauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

type TFASetupResponse struct {
	Secret      string `json:"secret"`
	OTPAuthURL  string `json:"otpauthUrl"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"accountName"`
}

type TFAEnableRequest struct {
	Code     string `json:"code" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TFAEnableResponse struct {
	BackupCodes []string `json:"backupCodes"`
}

type TFADisableRequest struct {
	Password string `json:"password" binding:"required"`
}

type TFAVerifyRequest struct {
	Code         string `json:"code" binding:"required"`
	IsBackupCode bool   `json:"isBackupCode,omitempty"`
}

const (
	sessionKeyPendingTFAUserID = "pending_tfa_user_id"
	sessionKeyPendingTFASecret = "pending_tfa_secret"
)

func (h *Handler) handleTFASetup(c *gin.Context) {
	user, err := GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: h.Options.Settings.Messages.Unauthorized})
		return
	}

	if user.TOTPEnabled {
		c.JSON(http.StatusConflict, ErrorResponse{Error: "tfa_already_enabled", Message: h.Options.Settings.Messages.TFAAlreadyEnabled})
		return
	}

	key, err := generateTOTPKey(&h.Options.Settings.TFA, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)
	session.Values[sessionKeyPendingTFASecret] = key.Secret()
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	c.JSON(http.StatusOK, TFASetupResponse{
		Secret:      key.Secret(),
		OTPAuthURL:  key.URL(),
		Issuer:      h.Options.Settings.TFA.Issuer,
		AccountName: tfaAccountLabel(&h.Options.Settings.TFA, user),
	})
}

func (h *Handler) handleTFAEnable(c *gin.Context) {
	user, err := GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: h.Options.Settings.Messages.Unauthorized})
		return
	}

	if user.TOTPEnabled {
		c.JSON(http.StatusConflict, ErrorResponse{Error: "tfa_already_enabled", Message: h.Options.Settings.Messages.TFAAlreadyEnabled})
		return
	}

	var req TFAEnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	valid, _, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_credentials", Message: h.Options.Settings.Messages.InvalidCredentials})
		return
	}

	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)
	pendingSecret, ok := session.Values[sessionKeyPendingTFASecret].(string)
	if !ok || pendingSecret == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "tfa_no_pending_setup", Message: "no pending TFA setup; call /tfa/setup first"})
		return
	}

	if !validateTOTPCode(pendingSecret, req.Code, &h.Options.Settings.TFA) {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_tfa_code", Message: h.Options.Settings.Messages.InvalidTFACode})
		return
	}

	var plain, hashed []string
	if h.Options.Settings.TFA.BackupCodeCount > 0 {
		plain, hashed, err = generateBackupCodes(h.Options.Settings.TFA.BackupCodeCount, h.Options.Settings.TFA.BackupCodeLength, h.Options.Settings.TFA.BackupCodeAlphabet, h.Options.Settings.HashingParams)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
			return
		}
	}

	now := time.Now()
	user.TOTPSecret = &pendingSecret
	user.TOTPEnabled = true
	user.TOTPEnrolledAt = &now
	user.BackupCodeHashes = hashed
	user.UpdatedAt = now

	if err := h.Options.Storage.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	delete(session.Values, sessionKeyPendingTFASecret)
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	c.JSON(http.StatusOK, TFAEnableResponse{BackupCodes: plain})
}

func (h *Handler) handleTFADisable(c *gin.Context) {
	user, err := GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: h.Options.Settings.Messages.Unauthorized})
		return
	}

	if !user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "tfa_not_enabled", Message: h.Options.Settings.Messages.TFANotEnabled})
		return
	}

	var req TFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	valid, _, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_credentials", Message: h.Options.Settings.Messages.InvalidCredentials})
		return
	}

	user.TOTPSecret = nil
	user.TOTPEnabled = false
	user.TOTPEnrolledAt = nil
	user.BackupCodeHashes = nil
	user.UpdatedAt = time.Now()

	if err := h.Options.Storage.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: h.Options.Settings.Messages.TFADisabled})
}

func (h *Handler) handleTFAVerify(c *gin.Context) {
	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)
	pendingID, ok := session.Values[sessionKeyPendingTFAUserID].(string)
	if !ok || pendingID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "tfa_no_pending_challenge", Message: h.Options.Settings.Messages.TFAPendingOnly})
		return
	}

	userID, err := uuid.Parse(pendingID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "tfa_no_pending_challenge", Message: h.Options.Settings.Messages.TFAPendingOnly})
		return
	}

	user, err := h.Options.Storage.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: h.Options.Settings.Messages.Unauthorized})
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "tfa_not_enabled", Message: h.Options.Settings.Messages.TFANotEnabled})
		return
	}

	// Budget already exhausted — reject without attempting verification so a
	// replayed pending cookie cannot brute-force past the limit.
	if max := h.Options.Settings.TFA.MaxVerifyAttempts; max > 0 && user.TOTPFailedAttempts >= max {
		delete(session.Values, sessionKeyPendingTFAUserID)
		_ = session.Save(c.Request, c.Writer)
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_tfa_code", Message: h.Options.Settings.Messages.InvalidTFACode})
		return
	}

	var req TFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	verified := false
	if !req.IsBackupCode {
		verified = validateTOTPCode(*user.TOTPSecret, req.Code, &h.Options.Settings.TFA)
	}

	if !verified && h.Options.Settings.TFA.BackupCodeCount > 0 {
		matchedHash, found := findBackupCodeMatch(user.BackupCodeHashes, req.Code)
		if found {
			consumed, cErr := h.consumeBackupCodeHash(user, matchedHash)
			if cErr != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
				return
			}
			verified = consumed
		}
	}

	if !verified {
		h.recordFailedTFAAttempt(c, session, user)
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_tfa_code", Message: h.Options.Settings.Messages.InvalidTFACode})
		return
	}

	if user.TOTPFailedAttempts != 0 {
		user.TOTPFailedAttempts = 0
		user.UpdatedAt = time.Now()
		if err := h.Options.Storage.UpdateUser(user); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
			return
		}
	}

	delete(session.Values, sessionKeyPendingTFAUserID)
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	if err := h.createSession(c, user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
	}

	c.Set("user", user)
	h.setUserInContext(c, user)

	c.JSON(http.StatusOK, SuccessResponse{
		Message: h.Options.Settings.Messages.TFASuccess,
		Data:    ToUserResponse(user),
	})
}

// consumeBackupCodeHash removes a verified backup code hash from the user.
// If Storage implements AtomicBackupCodeConsumer it is used (race-free);
// otherwise falls back to read-modify-write via Storage.UpdateUser.
// Returns true if the hash was removed, false if a racing request beat us to it.
func (h *Handler) consumeBackupCodeHash(user *User, hash string) (bool, error) {
	if atomic, ok := h.Options.Storage.(AtomicBackupCodeConsumer); ok {
		removed, err := atomic.ConsumeBackupCodeHash(user.ID, hash)
		if err != nil {
			return false, err
		}
		if removed {
			user.BackupCodeHashes = removeHash(user.BackupCodeHashes, hash)
		}
		return removed, nil
	}

	user.BackupCodeHashes = removeHash(user.BackupCodeHashes, hash)
	user.UpdatedAt = time.Now()
	if err := h.Options.Storage.UpdateUser(user); err != nil {
		return false, err
	}
	return true, nil
}

// recordFailedTFAAttempt increments the per-user attempt counter; when it
// reaches MaxVerifyAttempts the pending session is destroyed, forcing a
// fresh password login (which resets the counter in createPendingTFASession).
// The counter is persisted on the User record so that replaying the pending
// cookie cannot reset the budget.
func (h *Handler) recordFailedTFAAttempt(c *gin.Context, session *sessions.Session, user *User) {
	max := h.Options.Settings.TFA.MaxVerifyAttempts
	if max <= 0 {
		return
	}

	user.TOTPFailedAttempts++
	user.UpdatedAt = time.Now()
	_ = h.Options.Storage.UpdateUser(user)

	if user.TOTPFailedAttempts >= max {
		delete(session.Values, sessionKeyPendingTFAUserID)
		_ = session.Save(c.Request, c.Writer)
	}
}
