package basicauth

import "github.com/google/uuid"

// Storage persists users. The two-factor security state of a user (TOTPSecret,
// TOTPEnabled, TOTPEnrolledAt, BackupCodeHashes, TOTPFailedAttempts) is owned
// by the storage and changes only through the narrow operations below, each
// of which must be atomic on its own. UpdateUser must leave those fields
// untouched: the library passes whole User values that may have been read
// before a concurrent request (possibly on another replica) consumed a backup
// code or an attempt, and writing them back would undo that.
type Storage interface {
	CreateUser(user *User) error
	GetUserByUsername(username string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)
	// UpdateUser writes the profile fields (username, e-mail, password hash,
	// UpdatedAt, ...) and ignores the security fields listed above.
	UpdateUser(user *User) error
	DeleteUser(id uuid.UUID) error

	// ConsumeTOTPAttempt reserves one second-factor verification attempt
	// before a code is checked. If TOTPFailedAttempts is below max it is
	// incremented and the attempts left after this one (max minus the new
	// counter, never negative) are returned; otherwise nothing changes and
	// ErrTFAAttemptsExhausted is returned. The check and the increment must be
	// one atomic step, e.g. `UPDATE users SET failed = failed + 1 WHERE id = $1
	// AND failed < $max RETURNING $max - failed` (no row: exhausted).
	ConsumeTOTPAttempt(userID uuid.UUID, max int) (remaining int, err error)
	// ResetTOTPAttempts sets TOTPFailedAttempts to 0. Called after a
	// successful password step and after a successful code.
	ResetTOTPAttempts(userID uuid.UUID) error
	// ConsumeBackupCode atomically removes hash from BackupCodeHashes. It
	// returns true if the hash was present and removed, false if it was
	// already gone (a racing request used it first).
	ConsumeBackupCode(userID uuid.UUID, hash string) (bool, error)
	// SetTOTP enrols the user: stores secret and backupCodeHashes, sets
	// TOTPEnabled and TOTPEnrolledAt (now). Also used to regenerate.
	SetTOTP(userID uuid.UUID, secret string, backupCodeHashes []string) error
	// ClearTOTP disables two-factor authentication: clears TOTPSecret,
	// TOTPEnrolledAt and BackupCodeHashes and unsets TOTPEnabled.
	ClearTOTP(userID uuid.UUID) error

	// Future: API key authentication
	// GetUserByAPIKeyHash(apiKeyHash string) (*User, error)
	// UpdateAPIKey(userID uuid.UUID, apiKeyHash string) error
}
