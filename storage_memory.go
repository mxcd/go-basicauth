package basicauth

import (
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

	return user, nil
}

func (s *MemoryStorage) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[strings.ToLower(email)]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (s *MemoryStorage) GetUserByID(id uuid.UUID) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

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

	s.users[user.ID] = user

	if user.Username != nil {
		s.usersByUsername[strings.ToLower(*user.Username)] = user
	}
	if user.Email != nil {
		s.usersByEmail[strings.ToLower(*user.Email)] = user
	}

	return nil
}

// ConsumeBackupCodeHash atomically removes the given hash under the write lock,
// so concurrent calls for the same hash can't both succeed.
func (s *MemoryStorage) ConsumeBackupCodeHash(userID uuid.UUID, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists {
		return false, ErrUserNotFound
	}

	for i, h := range user.BackupCodeHashes {
		if h == hash {
			user.BackupCodeHashes = append(user.BackupCodeHashes[:i:i], user.BackupCodeHashes[i+1:]...)
			user.UpdatedAt = time.Now()
			return true, nil
		}
	}
	return false, nil
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
