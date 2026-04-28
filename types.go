package basicauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     *string   `json:"username,omitempty"`
	Email        *string   `json:"email,omitempty"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`

	IsTechnicalUser bool    `json:"isTechnicalUser"` // For future API key support
	APIKeyHash      *string `json:"-"`

	TOTPSecret         *string    `json:"-"`
	TOTPEnabled        bool       `json:"totpEnabled"`
	TOTPEnrolledAt     *time.Time `json:"totpEnrolledAt,omitempty"`
	BackupCodeHashes   []string   `json:"-"`
	TOTPFailedAttempts int        `json:"-"` // counter for MaxVerifyAttempts; resets on successful login or verify
}

type RegisterRequest struct {
	Username *string `json:"username" binding:"omitempty,min=3,max=50"`
	Email    *string `json:"email" binding:"omitempty,email"`
	Password string  `json:"password" binding:"required"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type UserResponse struct {
	ID              uuid.UUID `json:"id"`
	Username        *string   `json:"username,omitempty"`
	Email           *string   `json:"email,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	IsTechnicalUser bool      `json:"isTechnicalUser"`
	TOTPEnabled     bool      `json:"totpEnabled"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type PasswordRequirements struct {
	MinLength        int  `json:"minLength"`
	RequireUppercase bool `json:"requireUppercase"`
	RequireLowercase bool `json:"requireLowercase"`
	RequireNumbers   bool `json:"requireNumbers"`
	RequireSpecial   bool `json:"requireSpecial"`
}

type PublicPathType string

const (
	PublicPathExact  PublicPathType = "exact"
	PublicPathPrefix PublicPathType = "prefix"
)

type PublicPath struct {
	Type PublicPathType
	Path string
}

type PathAccessType string

const (
	PathAccessPublic  PathAccessType = "public"
	PathAccessPrivate PathAccessType = "private"
)

type PathRule struct {
	Type   PublicPathType
	Path   string
	Access PathAccessType
}

type Messages struct {
	RegistrationSuccess string
	LoginSuccess        string
	LogoutSuccess       string
	InvalidCredentials  string
	UserAlreadyExists   string
	PasswordTooWeak     string
	InternalError       string
	Unauthorized        string

	TFARequired       string
	TFASuccess        string
	InvalidTFACode    string
	TFAAlreadyEnabled string
	TFANotEnabled     string
	TFAPendingOnly    string
	TFADisabled       string
	TFASetupRequired  string
}

type TFASettings struct {
	Issuer             string             // otpauth issuer label, required when TFA enabled
	AccountLabel       func(*User) string // otpauth account label, defaults to username or email
	Period             uint               // seconds per code, default 30
	Digits             uint               // digits per code, default 6
	SkewWindows        uint               // ± period tolerance, default 1
	BackupCodeCount    int                // codes issued on enable; 0 disables backup codes
	BackupCodeLength   int                // characters per backup code, default 10
	BackupCodeAlphabet string             // characters to draw from, default "0123456789"
	PendingSessionTTL  time.Duration      // lifetime of the post-password pre-TFA session
	MaxVerifyAttempts  int                // wrong-code attempts allowed before pending session dies; 0 = unlimited, default 5
	Required           bool               // when true, authenticated users must enroll before reaching protected routes
}

type BasicAuthSettings struct {
	EnableUsernameLogin bool
	EnableEmailLogin    bool
	EnableTFA           bool

	SessionName          string
	SessionExpiration    time.Duration
	SessionSecretKey     []byte // 64 bytes for HMAC-SHA256
	SessionEncryptionKey []byte // 32 bytes for AES-256

	CookieSecure   bool
	CookieHttpOnly bool
	CookieSameSite http.SameSite
	CookiePath     string
	CookieDomain   string

	PublicPaths []PublicPath // Deprecated: use PathRules instead
	PathRules   []PathRule

	PasswordRequirements PasswordRequirements
	TFA                  TFASettings
	Messages             Messages
	HashingParams        Params
}

func DefaultSettings() *BasicAuthSettings {
	return &BasicAuthSettings{
		EnableUsernameLogin: true,
		EnableEmailLogin:    true,
		EnableTFA:           false,
		SessionName:         "basicauth_session",
		SessionExpiration:   24 * time.Hour,
		CookieSecure:        true,
		CookieHttpOnly:      true,
		CookieSameSite:      http.SameSiteLaxMode,
		CookiePath:          "/",
		CookieDomain:        "",
		PasswordRequirements: PasswordRequirements{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSpecial:   false,
		},
		TFA: TFASettings{
			Period:             30,
			Digits:             6,
			SkewWindows:        1,
			BackupCodeCount:    10,
			BackupCodeLength:   10,
			BackupCodeAlphabet: "0123456789",
			PendingSessionTTL:  5 * time.Minute,
			MaxVerifyAttempts:  5,
		},
		Messages: Messages{
			RegistrationSuccess: "Registration successful",
			LoginSuccess:        "Login successful",
			LogoutSuccess:       "Logout successful",
			InvalidCredentials:  "Invalid credentials",
			UserAlreadyExists:   "User already exists",
			PasswordTooWeak:     "Password does not meet requirements",
			InternalError:       "Internal server error",
			Unauthorized:        "Unauthorized",
			TFARequired:         "Two-factor authentication required",
			TFASuccess:          "Two-factor authentication successful",
			InvalidTFACode:      "Invalid two-factor authentication code",
			TFAAlreadyEnabled:   "Two-factor authentication is already enabled",
			TFANotEnabled:       "Two-factor authentication is not enabled",
			TFAPendingOnly:      "No pending two-factor authentication challenge",
			TFADisabled:         "Two-factor authentication disabled",
			TFASetupRequired:    "Two-factor authentication setup required",
		},
		HashingParams: DefaultPasswordHashingParams,
	}
}

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrInvalidUsername      = errors.New("invalid username format")
	ErrPasswordTooWeak      = errors.New("password does not meet requirements")
	ErrSessionNotFound      = errors.New("session not found")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrInternalServer       = errors.New("internal server error")
	ErrMissingCredentials   = errors.New("username or email required")
	ErrRegistrationDisabled = errors.New("registration method not enabled")
	ErrTFARequired          = errors.New("two-factor authentication required")
	ErrTFAAlreadyEnabled    = errors.New("two-factor authentication already enabled")
	ErrTFANotEnabled        = errors.New("two-factor authentication not enabled")
	ErrInvalidTFACode       = errors.New("invalid two-factor authentication code")
	ErrTFAPendingOnly       = errors.New("no pending two-factor authentication challenge")
	ErrTFASetupRequired     = errors.New("two-factor authentication setup required")
)
