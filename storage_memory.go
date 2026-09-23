package basicauth

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type MemoryStorage struct {
	users           map[uuid.UUID]*User
	usersByUsername map[string]*User
	usersByEmail    map[string]*User
	mu              sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:           make(map[uuid.UUID]*User),
		usersByUsername: make(map[string]*User),
		usersByEmail:    make(map[string]*User),
	}
}

func (s *MemoryStorage) CreateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return ErrUserAlreadyExists
	}

	if user.Username != nil {
		username := strings.ToLower(*user.Username)
		if _, exists := s.usersByUsername[username]; exists {
			return ErrUserAlreadyExists
		}
	}

	if user.Email != nil {
		email := strings.ToLower(*user.Email)
		if _, exists := s.usersByEmail[email]; exists {
			return ErrUserAlreadyExists
		}
	}

	user = cloneUser(user)
	s.users[user.ID] = user

	if user.Username != nil {
		s.usersByUsername[strings.ToLower(*user.Username)] = user
	}

	if user.Email != nil {
		s.usersByEmail[strings.ToLower(*user.Email)] = user
	}

	return nil
}

func (s *MemoryStorage) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByUsername[strings.ToLower(username)]
	if !exists {
		return nil, ErrUserNotFound
	}

	return cloneUser(user), nil
}

func (s *MemoryStorage) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[strings.ToLower(email)]
	if !exists {
		return nil, ErrUserNotFound
	}

	return cloneUser(user), nil
}

func (s *MemoryStorage) GetUserByID(id uuid.UUID) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return cloneUser(user), nil
}

// UpdateUser writes the profile fields and keeps the stored security state
// (see Storage), which only the narrow operations below may change.
func (s *MemoryStorage) UpdateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existingUser, exists := s.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}

	if existingUser.Username != nil {
		delete(s.usersByUsername, strings.ToLower(*existingUser.Username))
	}
	if existingUser.Email != nil {
		delete(s.usersByEmail, strings.ToLower(*existingUser.Email))
	}

	updated := cloneUser(user)
	updated.TOTPSecret = existingUser.TOTPSecret
	updated.TOTPEnabled = existingUser.TOTPEnabled
	updated.TOTPEnrolledAt = existingUser.TOTPEnrolledAt
	updated.BackupCodeHashes = existingUser.BackupCodeHashes
	updated.TOTPFailedAttempts = existingUser.TOTPFailedAttempts
	s.users[user.ID] = updated

	if updated.Username != nil {
		s.usersByUsername[strings.ToLower(*updated.Username)] = updated
	}
	if updated.Email != nil {
		s.usersByEmail[strings.ToLower(*updated.Email)] = updated
	}

	return nil
}

// withUser runs fn on the stored user under the write lock.
func (s *MemoryStorage) withUser(id uuid.UUID, fn func(*User) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}
	return fn(user)
}

func (s *MemoryStorage) ConsumeTOTPAttempt(userID uuid.UUID, max int) (int, error) {
	remaining := 0
	err := s.withUser(userID, func(u *User) error {
		if u.TOTPFailedAttempts >= max {
			return ErrTFAAttemptsExhausted
		}
		u.TOTPFailedAttempts++
		remaining = max - u.TOTPFailedAttempts
		return nil
	})
	return remaining, err
}

func (s *MemoryStorage) ResetTOTPAttempts(userID uuid.UUID) error {
	return s.withUser(userID, func(u *User) error {
		u.TOTPFailedAttempts = 0
		return nil
	})
}

func (s *MemoryStorage) ConsumeBackupCode(userID uuid.UUID, hash string) (bool, error) {
	removed := false
	err := s.withUser(userID, func(u *User) error {
		for i, h := range u.BackupCodeHashes {
			if h == hash {
				u.BackupCodeHashes = append(u.BackupCodeHashes[:i:i], u.BackupCodeHashes[i+1:]...)
				u.UpdatedAt = time.Now()
				removed = true
				return nil
			}
		}
		return nil
	})
	return removed, err
}

func (s *MemoryStorage) SetTOTP(userID uuid.UUID, secret string, backupCodeHashes []string) error {
	return s.withUser(userID, func(u *User) error {
		now := time.Now()
		u.TOTPSecret = &secret
		u.TOTPEnabled = true
		u.TOTPEnrolledAt = &now
		u.BackupCodeHashes = slices.Clone(backupCodeHashes)
		u.UpdatedAt = now
		return nil
	})
}

func (s *MemoryStorage) ClearTOTP(userID uuid.UUID) error {
	return s.withUser(userID, func(u *User) error {
		u.TOTPSecret = nil
		u.TOTPEnabled = false
		u.TOTPEnrolledAt = nil
		u.BackupCodeHashes = nil
		u.UpdatedAt = time.Now()
		return nil
	})
}

func (s *MemoryStorage) DeleteUser(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}

	delete(s.users, id)

	if user.Username != nil {
		delete(s.usersByUsername, strings.ToLower(*user.Username))
	}

	if user.Email != nil {
		delete(s.usersByEmail, strings.ToLower(*user.Email))
	}

	return nil
}

// cloneUser copies u deep enough that neither side can change the other's
// slices or pointed-to values.
func cloneUser(u *User) *User {
	c := *u
	c.BackupCodeHashes = slices.Clone(u.BackupCodeHashes)
	if u.TOTPSecret != nil {
		secret := *u.TOTPSecret
		c.TOTPSecret = &secret
	}
	return &c
}
