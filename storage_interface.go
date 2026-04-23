package basicauth

import "github.com/google/uuid"

type Storage interface {
	CreateUser(user *User) error
	GetUserByUsername(username string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)
	UpdateUser(user *User) error
	DeleteUser(id uuid.UUID) error

	// Future: API key authentication
	// GetUserByAPIKeyHash(apiKeyHash string) (*User, error)
	// UpdateAPIKey(userID uuid.UUID, apiKeyHash string) error
}

// AtomicBackupCodeConsumer is an optional capability. If your Storage
// implements it, the library uses it to consume backup codes race-free
// instead of the default read-modify-write via UpdateUser. This matters
// when the same backup code could be submitted by two concurrent requests —
// an atomic implementation guarantees exactly one of them succeeds.
// SQL-backed stores typically implement this via a conditional UPDATE
// (e.g. `UPDATE ... SET backup_codes = array_remove(..., $hash)
// WHERE id = $id AND $hash = ANY(backup_codes)`).
type AtomicBackupCodeConsumer interface {
	// ConsumeBackupCodeHash atomically removes hash from the user's
	// BackupCodeHashes. Returns true if the hash was present and removed,
	// false if it was already gone (racing request beat this one).
	ConsumeBackupCodeHash(userID uuid.UUID, hash string) (bool, error)
}
