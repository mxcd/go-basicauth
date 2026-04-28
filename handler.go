package basicauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

type Options struct {
	Engine                *gin.Engine
	AuthenticationBaseUrl string
	Storage               Storage
	Settings              *BasicAuthSettings

	// UserKey is the key used to store the user in context.Context.
	// If nil, user is not stored in context (backward compatible).
	UserKey any

	// UserTransformer is an optional function to convert basicauth.User before storing in context.
	// If nil, the basicauth.User is stored directly.
	// The returned value is stored in context under UserKey.
	UserTransformer func(c *gin.Context, user *User) any
}

type Handler struct {
	Options      *Options
	sessionStore *sessions.CookieStore
}

func NewHandler(options *Options) (*Handler, error) {
	if options.Engine == nil {
		return nil, errors.New("gin engine is required")
	}
	if options.Storage == nil {
		return nil, errors.New("storage implementation is required")
	}

	if options.Settings == nil {
		options.Settings = DefaultSettings()
	}

	if len(options.Settings.SessionSecretKey) != 64 {
		return nil, errors.New("session secret key must be 64 bytes (for HMAC-SHA256)")
	}
	if len(options.Settings.SessionEncryptionKey) != 32 {
		return nil, errors.New("session encryption key must be 32 bytes (for AES-256)")
	}

	store := sessions.NewCookieStore(
		options.Settings.SessionSecretKey,
		options.Settings.SessionEncryptionKey,
	)

	// store.MaxAge(n) updates the securecookie codec's server-side expiry
	// validator. Without it, the codec keeps gorilla's 30-day default and
	// accepts replayed cookies far beyond SessionExpiration — overriding
	// store.Options below only affects the Set-Cookie header client-side.
	store.MaxAge(int(options.Settings.SessionExpiration.Seconds()))

	store.Options = &sessions.Options{
		Path:     options.Settings.CookiePath,
		Domain:   options.Settings.CookieDomain,
		MaxAge:   int(options.Settings.SessionExpiration.Seconds()),
		Secure:   options.Settings.CookieSecure,
		HttpOnly: options.Settings.CookieHttpOnly,
		SameSite: options.Settings.CookieSameSite,
	}

	return &Handler{
		Options:      options,
		sessionStore: store,
	}, nil
}

func (h *Handler) RegisterRoutes() error {
	baseUrl := h.Options.AuthenticationBaseUrl
	if baseUrl == "" {
		baseUrl = "/auth"
	}

	h.Options.Engine.Use(h.RequireAuth())

	authGroup := h.Options.Engine.Group(baseUrl)
	{
		authGroup.POST("/register", h.handleRegister)
		authGroup.POST("/login", h.handleLogin)
		authGroup.POST("/logout", h.handleLogout)
		authGroup.GET("/me", h.handleMe)

		if h.Options.Settings.EnableTFA {
			tfaGroup := authGroup.Group("/tfa")
			tfaGroup.POST("/setup", h.handleTFASetup)
			tfaGroup.POST("/enable", h.handleTFAEnable)
			tfaGroup.POST("/disable", h.handleTFADisable)
			tfaGroup.POST("/verify", h.handleTFAVerify)
		}
	}

	return nil
}

func (h *Handler) getUserFromSession(c *gin.Context) (*User, error) {
	session, err := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	userID, ok := session.Values["user_id"].(string)
	if !ok || userID == "" {
		return nil, ErrSessionNotFound
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	return h.Options.Storage.GetUserByID(id)
}

func (h *Handler) createSession(c *gin.Context, user *User) error {
	// gorilla/sessions Get() may error on invalid cookies but still returns usable session
	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)

	session.Values["user_id"] = user.ID.String()
	return session.Save(c.Request, c.Writer)
}

func (h *Handler) createPendingTFASession(c *gin.Context, user *User) error {
	// Reset the per-user failed-attempt counter: each fresh password-auth
	// earns a new budget. An attacker replaying an old pending cookie cannot
	// reset it because reaching this path requires knowing the password.
	if user.TOTPFailedAttempts != 0 {
		user.TOTPFailedAttempts = 0
		user.UpdatedAt = time.Now()
		if err := h.Options.Storage.UpdateUser(user); err != nil {
			return err
		}
	}

	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)

	delete(session.Values, "user_id")
	session.Values[sessionKeyPendingTFAUserID] = user.ID.String()

	ttl := h.Options.Settings.TFA.PendingSessionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	session.Options.MaxAge = int(ttl.Seconds())

	return session.Save(c.Request, c.Writer)
}

func (h *Handler) destroySession(c *gin.Context) error {
	session, _ := h.sessionStore.Get(c.Request, h.Options.Settings.SessionName)

	session.Options.MaxAge = -1
	return session.Save(c.Request, c.Writer)
}

// setUserInContext stores the user in the request context if UserKey is configured.
// If UserTransformer is provided, the user is transformed before storing.
func (h *Handler) setUserInContext(c *gin.Context, user *User) {
	if h.Options.UserKey == nil {
		return
	}

	var userToStore any = user
	if h.Options.UserTransformer != nil {
		userToStore = h.Options.UserTransformer(c, user)
	}

	ctx := context.WithValue(c.Request.Context(), h.Options.UserKey, userToStore)
	c.Request = c.Request.WithContext(ctx)
}

func (h *Handler) getUserByIdentifier(identifier string) (*User, error) {
	settings := h.Options.Settings
	isEmail := strings.Contains(identifier, "@")

	if isEmail {
		if !settings.EnableEmailLogin {
			return nil, ErrInvalidCredentials
		}
		return h.Options.Storage.GetUserByEmail(identifier)
	}

	if !settings.EnableUsernameLogin {
		return nil, ErrInvalidCredentials
	}
	return h.Options.Storage.GetUserByUsername(identifier)
}

func (h *Handler) handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	if req.Username == nil && req.Email == nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: ErrMissingCredentials.Error(),
		})
		return
	}

	if req.Username != nil && !h.Options.Settings.EnableUsernameLogin {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: ErrRegistrationDisabled.Error(),
		})
		return
	}

	if req.Email != nil && !h.Options.Settings.EnableEmailLogin {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: ErrRegistrationDisabled.Error(),
		})
		return
	}

	if req.Username != nil {
		if err := validateUsername(*req.Username); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "invalid_username",
				Message: err.Error(),
			})
			return
		}
	}

	if req.Email != nil {
		if err := validateEmail(*req.Email); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "invalid_email",
				Message: err.Error(),
			})
			return
		}
	}

	if err := validatePassword(req.Password, h.Options.Settings.PasswordRequirements); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "weak_password",
			Message: h.Options.Settings.Messages.PasswordTooWeak,
		})
		return
	}

	if req.Username != nil {
		if _, err := h.Options.Storage.GetUserByUsername(*req.Username); err == nil {
			c.JSON(http.StatusConflict, ErrorResponse{
				Error:   "user_exists",
				Message: h.Options.Settings.Messages.UserAlreadyExists,
			})
			return
		}
	}

	if req.Email != nil {
		if _, err := h.Options.Storage.GetUserByEmail(*req.Email); err == nil {
			c.JSON(http.StatusConflict, ErrorResponse{
				Error:   "user_exists",
				Message: h.Options.Settings.Messages.UserAlreadyExists,
			})
			return
		}
	}

	hash, err := HashPassword(req.Password, h.Options.Settings.HashingParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: h.Options.Settings.Messages.InternalError,
		})
		return
	}

	now := time.Now()
	user := &User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.Options.Storage.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: h.Options.Settings.Messages.InternalError,
		})
		return
	}

	if err := h.createSession(c, user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: h.Options.Settings.Messages.InternalError,
		})
		return
	}

	h.setUserInContext(c, user)

	c.JSON(http.StatusCreated, SuccessResponse{
		Message: h.Options.Settings.Messages.RegistrationSuccess,
		Data:    ToUserResponse(user),
	})
}

func (h *Handler) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	user, err := h.getUserByIdentifier(req.Identifier)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: h.Options.Settings.Messages.InvalidCredentials,
		})
		return
	}

	valid, _, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: h.Options.Settings.Messages.InvalidCredentials,
		})
		return
	}

	if h.Options.Settings.EnableTFA && user.TOTPEnabled && user.TOTPSecret != nil {
		if err := h.createPendingTFASession(c, user); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "internal_error",
				Message: h.Options.Settings.Messages.InternalError,
			})
			return
		}
		c.JSON(http.StatusAccepted, SuccessResponse{
			Message: h.Options.Settings.Messages.TFARequired,
			Data:    gin.H{"tfaRequired": true},
		})
		return
	}

	if err := h.createSession(c, user); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: h.Options.Settings.Messages.InternalError,
		})
		return
	}

	h.setUserInContext(c, user)

	c.JSON(http.StatusOK, SuccessResponse{
		Message: h.Options.Settings.Messages.LoginSuccess,
		Data:    ToUserResponse(user),
	})
}

func (h *Handler) handleLogout(c *gin.Context) {
	if err := h.destroySession(c); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: h.Options.Settings.Messages.InternalError,
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: h.Options.Settings.Messages.LogoutSuccess,
	})
}

func (h *Handler) handleMe(c *gin.Context) {
	user, err := GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: h.Options.Settings.Messages.Unauthorized,
		})
		return
	}

	c.JSON(http.StatusOK, ToUserResponse(user))
}

func (h *Handler) RequireAuth() gin.HandlerFunc {
	baseUrl := h.Options.AuthenticationBaseUrl
	if baseUrl == "" {
		baseUrl = "/auth"
	}

	// Auth endpoints with hardcoded access rules
	publicAuthPaths := map[string]bool{
		baseUrl + "/register":   true,
		baseUrl + "/login":      true,
		baseUrl + "/tfa/verify": true, // reachable only with a pending session; handler enforces
	}
	protectedAuthPaths := map[string]bool{
		baseUrl + "/logout":      true,
		baseUrl + "/me":          true,
		baseUrl + "/tfa/setup":   true,
		baseUrl + "/tfa/enable":  true,
		baseUrl + "/tfa/disable": true,
	}
	// When TFA.Required is set, these paths stay reachable for authenticated
	// but not-yet-enrolled users so they can complete enrollment.
	tfaSetupBypassPaths := map[string]bool{
		baseUrl + "/logout":     true,
		baseUrl + "/me":         true,
		baseUrl + "/tfa/setup":  true,
		baseUrl + "/tfa/enable": true,
	}

	return func(c *gin.Context) {
		requestPath := c.Request.URL.Path

		// Register and login are always public
		if publicAuthPaths[requestPath] {
			c.Next()
			return
		}

		// Logout and me are always protected - skip to auth check below
		if protectedAuthPaths[requestPath] {
			// Fall through to authentication check
		} else {
			// For non-auth endpoints, check path rules
			// Find the longest matching rule
			matchedRule, found := h.findLongestMatchingRule(requestPath)

			// If a rule matched and it's public, allow access
			if found && matchedRule.Access == PathAccessPublic {
				c.Next()
				return
			}
		}

		// If a rule matched and it's private, or no rule matched, require auth
		user, err := h.getUserFromSession(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: h.Options.Settings.Messages.Unauthorized,
			})
			c.Abort()
			return
		}

		if h.Options.Settings.EnableTFA && h.Options.Settings.TFA.Required && !user.TOTPEnabled && !tfaSetupBypassPaths[requestPath] {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error:   "tfa_setup_required",
				Message: h.Options.Settings.Messages.TFASetupRequired,
			})
			c.Abort()
			return
		}

		c.Set("user", user)

		h.setUserInContext(c, user)

		c.Next()
	}
}

func (h *Handler) findLongestMatchingRule(requestPath string) (PathRule, bool) {
	var longestMatch PathRule
	var longestLength int
	found := false

	// Convert PublicPaths to PathRules for backward compatibility
	allRules := make([]PathRule, 0, len(h.Options.Settings.PublicPaths)+len(h.Options.Settings.PathRules))
	for _, pp := range h.Options.Settings.PublicPaths {
		allRules = append(allRules, PathRule{
			Type:   pp.Type,
			Path:   pp.Path,
			Access: PathAccessPublic,
		})
	}
	allRules = append(allRules, h.Options.Settings.PathRules...)

	// Find all matching rules and select the longest
	for _, rule := range allRules {
		if h.ruleMatches(requestPath, rule) {
			matchLength := len(rule.Path)
			if matchLength > longestLength {
				longestMatch = rule
				longestLength = matchLength
				found = true
			}
		}
	}

	return longestMatch, found
}

func (h *Handler) ruleMatches(requestPath string, rule PathRule) bool {
	switch rule.Type {
	case PublicPathExact:
		return requestPath == rule.Path
	case PublicPathPrefix:
		return strings.HasPrefix(requestPath, rule.Path)
	default:
		return false
	}
}
