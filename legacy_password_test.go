package basicauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func setupLegacyTest(t *testing.T, password string) (*MemoryStorage, *gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("seed bcrypt hash: %v", err)
	}

	email := "migrated@example.com"
	now := time.Now()
	if err := storage.CreateUser(&User{
		ID:           uuid.New(),
		Email:        &email,
		PasswordHash: string(bcryptHash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	settings := DefaultSettings()
	settings.SessionSecretKey, _ = GenerateSessionSecretKey()
	settings.SessionEncryptionKey, _ = GenerateSessionEncryptionKey()
	settings.LegacyPasswordVerifier = BcryptVerifier

	handler, err := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	handler.RegisterRoutes()

	return storage, r, email
}

func postLogin(t *testing.T, r *gin.Engine, identifier, password string) int {
	t.Helper()
	body, _ := json.Marshal(LoginRequest{Identifier: identifier, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestLegacyBcryptLogin_UpgradesToArgon2id(t *testing.T) {
	const password = "Sup3rSecret!"
	storage, r, email := setupLegacyTest(t, password)

	// Correct password against a bcrypt hash must authenticate.
	if code := postLogin(t, r, email, password); code != http.StatusOK {
		t.Fatalf("legacy login: want 200, got %d", code)
	}

	// And the stored hash must now be argon2id (transparent upgrade).
	user, err := storage.GetUserByEmail(email)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if !strings.HasPrefix(user.PasswordHash, "$argon2id$") {
		t.Fatalf("hash not upgraded: %q", user.PasswordHash)
	}
	if ok, _, err := VerifyPassword(password, user.PasswordHash); err != nil || !ok {
		t.Fatalf("upgraded hash does not verify natively: ok=%v err=%v", ok, err)
	}

	// Subsequent login goes through the native path and still works.
	if code := postLogin(t, r, email, password); code != http.StatusOK {
		t.Fatalf("post-upgrade login: want 200, got %d", code)
	}
}

func TestLegacyBcryptLogin_WrongPasswordRejected(t *testing.T) {
	const password = "Sup3rSecret!"
	storage, r, email := setupLegacyTest(t, password)

	if code := postLogin(t, r, email, "wrong-password"); code != http.StatusUnauthorized {
		t.Fatalf("wrong legacy password: want 401, got %d", code)
	}

	// A rejected login must not rewrite the stored hash.
	user, _ := storage.GetUserByEmail(email)
	if !strings.HasPrefix(user.PasswordHash, "$2") {
		t.Fatalf("bcrypt hash was mutated on failed login: %q", user.PasswordHash)
	}
}

// Without a verifier configured, a legacy hash must not authenticate at all.
func TestLegacyHash_NoVerifier_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	const password = "Sup3rSecret!"
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	email := "migrated@example.com"
	now := time.Now()
	_ = storage.CreateUser(&User{
		ID:           uuid.New(),
		Email:        &email,
		PasswordHash: string(bcryptHash),
		CreatedAt:    now,
		UpdatedAt:    now,
	})

	settings := DefaultSettings()
	settings.SessionSecretKey, _ = GenerateSessionSecretKey()
	settings.SessionEncryptionKey, _ = GenerateSessionEncryptionKey()
	// No LegacyPasswordVerifier set.

	handler, err := NewHandler(&Options{Engine: r, AuthenticationBaseUrl: "/auth", Storage: storage, Settings: settings})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	handler.RegisterRoutes()

	if code := postLogin(t, r, email, password); code != http.StatusUnauthorized {
		t.Fatalf("legacy hash without verifier: want 401, got %d", code)
	}
}
