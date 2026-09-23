package basicauth

import (
	"errors"
	"net/http"

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

	if err := h.Options.Storage.SetTOTP(user.ID, pendingSecret, hashed); err != nil {
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

	if err := h.Options.Storage.ClearTOTP(user.ID); err != nil {
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

	var req TFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	// Reserve an attempt before verifying anything: the budget is checked and
	// spent in one storage step, so neither a replayed pending cookie nor
	// concurrent requests on several replicas can verify more than max codes.
	// A successful code resets the counter below.
	max := h.Options.Settings.TFA.MaxVerifyAttempts
	remaining := 0
	if max > 0 {
		remaining, err = h.Options.Storage.ConsumeTOTPAttempt(user.ID, max)
		if errors.Is(err, ErrTFAAttemptsExhausted) {
			h.endPendingTFA(c, session)
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_tfa_code", Message: h.Options.Settings.Messages.InvalidTFACode})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
			return
		}
	}

	verified := false
	if !req.IsBackupCode {
		verified = validateTOTPCode(*user.TOTPSecret, req.Code, &h.Options.Settings.TFA)
	}

	if !verified && h.Options.Settings.TFA.BackupCodeCount > 0 {
		matchedHash, found := findBackupCodeMatch(user.BackupCodeHashes, req.Code)
		if found {
			consumed, cErr := h.Options.Storage.ConsumeBackupCode(user.ID, matchedHash)
			if cErr != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
				return
			}
			verified = consumed
		}
	}

	if !verified {
		// The attempt is already counted; the last one ends the pending
		// session, forcing a fresh password login for a new budget.
		if max > 0 && remaining == 0 {
			h.endPendingTFA(c, session)
		}
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid_tfa_code", Message: h.Options.Settings.Messages.InvalidTFACode})
		return
	}

	if err := h.Options.Storage.ResetTOTPAttempts(user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal_error", Message: h.Options.Settings.Messages.InternalError})
		return
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

func (h *Handler) endPendingTFA(c *gin.Context, session *sessions.Session) {
	delete(session.Values, sessionKeyPendingTFAUserID)
	_ = session.Save(c.Request, c.Writer)
}
