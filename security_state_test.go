package basicauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

// spyStorage wraps MemoryStorage to count UpdateUser calls and to run a
// one-shot callback right after GetUserByUsername has handed out its snapshot, which
// is where a concurrent request on another replica can interleave.
type spyStorage struct {
	*MemoryStorage
	updateUserCalls atomic.Int32
	afterRead       atomic.Pointer[func(*User)]
	// loseBackupCodeRace makes ConsumeBackupCode report that a racing
	// request removed the hash first.
	loseBackupCodeRace atomic.Bool
}

func (s *spyStorage) ConsumeBackupCode(userID uuid.UUID, hash string) (bool, error) {
	if s.loseBackupCodeRace.Load() {
		return false, nil
	}
	return s.MemoryStorage.ConsumeBackupCode(userID, hash)
}

func (s *spyStorage) UpdateUser(user *User) error {
	s.updateUserCalls.Add(1)
	return s.MemoryStorage.UpdateUser(user)
}

func (s *spyStorage) GetUserByUsername(username string) (*User, error) {
	user, err := s.MemoryStorage.GetUserByUsername(username)
	if fn := s.afterRead.Swap(nil); err == nil && fn != nil {
		(*fn)(user)
	}
	return user, err
}

func setupSpyServer(t *testing.T, settings *BasicAuthSettings) (*spyStorage, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := &spyStorage{MemoryStorage: NewMemoryStorage()}
	settings.EnableRegistration = true
	settings.SessionSecretKey, _ = GenerateSessionSecretKey()
	settings.SessionEncryptionKey, _ = GenerateSessionEncryptionKey()
	handler, err := NewHandler(&Options{Engine: r, AuthenticationBaseUrl: "/auth", Storage: storage, Settings: settings})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	handler.RegisterRoutes()
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return storage, server
}

func loginPending(t *testing.T, serverURL string) *http.Client {
	t.Helper()
	client := clientWithJar(t)
	resp := doJSON(t, client, "POST", serverURL+"/auth/login", map[string]any{"identifier": "alice", "password": "Password123"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("login: expected 202, got %d", resp.StatusCode)
	}
	return client
}

func verifyCode(t *testing.T, client *http.Client, serverURL, code string, backup bool) int {
	t.Helper()
	status, _ := verifyCodeError(t, client, serverURL, code, backup)
	return status
}

func verifyCodeError(t *testing.T, client *http.Client, serverURL, code string, backup bool) (int, string) {
	t.Helper()
	resp := doJSON(t, client, "POST", serverURL+"/auth/tfa/verify", map[string]any{"code": code, "isBackupCode": backup})
	defer resp.Body.Close()
	var body ErrorResponse
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Error
}

// assertPendingSessionEnded refills the budget and submits a valid code: a
// pending session that is still alive would let it in.
func assertPendingSessionEnded(t *testing.T, storage *spyStorage, client *http.Client, serverURL, secret string) {
	t.Helper()
	if err := storage.ResetTOTPAttempts(aliceID(t, storage)); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	status, errCode := verifyCodeError(t, client, serverURL, code, false)
	if status != http.StatusUnauthorized || errCode != "tfa_no_pending_challenge" {
		t.Fatalf("pending session must be gone: got %d %q", status, errCode)
	}
}

func aliceID(t *testing.T, s *spyStorage) uuid.UUID {
	t.Helper()
	u, err := s.MemoryStorage.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("get alice: %v", err)
	}
	return u.ID
}

// A spent budget refuses the request before the code is looked at: even a
// valid code is rejected, and the pending session ends.
func TestTFA_AttemptBudgetCheckedBeforeVerification(t *testing.T) {
	storage, server := setupSpyServer(t, tfaSettings())
	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)

	client := loginPending(t, server.URL)
	id := aliceID(t, storage)
	for range 5 { // the default MaxVerifyAttempts, spent elsewhere
		if _, err := storage.ConsumeTOTPAttempt(id, 5); err != nil {
			t.Fatalf("consume: %v", err)
		}
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	if got := verifyCode(t, client, server.URL, code, false); got != http.StatusUnauthorized {
		t.Fatalf("valid code with a spent budget: expected 401, got %d", got)
	}
	assertPendingSessionEnded(t, storage, client, server.URL, secret)

	// A fresh password step resets the budget.
	client = loginPending(t, server.URL)
	if got := verifyCode(t, client, server.URL, code, false); got != http.StatusOK {
		t.Fatalf("after re-login: expected 200, got %d", got)
	}
	u, _ := storage.MemoryStorage.GetUserByID(id)
	if u.TOTPFailedAttempts != 0 {
		t.Errorf("successful code must reset the counter, got %d", u.TOTPFailedAttempts)
	}
}

// Replica A reads alice for a password login, replica B consumes a backup
// code, then A completes the login including a whole-user write-back (the
// legacy hash upgrade). The code must stay consumed.
func TestTFA_ConsumedBackupCodeStaysConsumed(t *testing.T) {
	settings := tfaSettings()
	settings.LegacyPasswordVerifier = func(password, storedHash string) (bool, error) {
		return storedHash == "legacy:"+password, nil
	}
	storage, server := setupSpyServer(t, settings)
	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	_, codes := enrollTFA(t, setup, server.URL)

	id := aliceID(t, storage)
	u, _ := storage.MemoryStorage.GetUserByID(id)
	u.PasswordHash = "legacy:Password123" // forces UpdateUser during login
	if err := storage.MemoryStorage.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	consumedHash, ok := findBackupCodeMatch(u.BackupCodeHashes, codes[0])
	if !ok {
		t.Fatal("backup code hash not found")
	}

	consume := func(snapshot *User) {
		if removed, err := storage.ConsumeBackupCode(snapshot.ID, consumedHash); err != nil || !removed {
			t.Errorf("replica B consume: removed=%v err=%v", removed, err)
		}
	}
	storage.afterRead.Store(&consume)
	loginPending(t, server.URL)

	if storage.updateUserCalls.Load() == 0 {
		t.Fatal("the scenario needs a whole-user write-back during login")
	}
	stored, _ := storage.MemoryStorage.GetUserByID(id)
	if stored.PasswordHash == "legacy:Password123" {
		t.Error("legacy hash was not upgraded")
	}
	if _, found := findBackupCodeMatch(stored.BackupCodeHashes, codes[0]); found {
		t.Fatal("write-back restored a consumed backup code")
	}
	client := loginPending(t, server.URL)
	if got := verifyCode(t, client, server.URL, codes[0], true); got != http.StatusUnauthorized {
		t.Errorf("consumed backup code: expected 401, got %d", got)
	}
}

// The whole two-factor lifecycle goes through the narrow operations only.
func TestTFA_LifecycleNeverCallsUpdateUser(t *testing.T) {
	storage, server := setupSpyServer(t, tfaSettings())
	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, codes := enrollTFA(t, setup, server.URL)

	client := loginPending(t, server.URL)
	if got := verifyCode(t, client, server.URL, "000000", false); got != http.StatusUnauthorized {
		t.Fatalf("wrong code: expected 401, got %d", got)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if got := verifyCode(t, client, server.URL, code, false); got != http.StatusOK {
		t.Fatalf("totp: expected 200, got %d", got)
	}
	client = loginPending(t, server.URL)
	if got := verifyCode(t, client, server.URL, codes[0], true); got != http.StatusOK {
		t.Fatalf("backup code: expected 200, got %d", got)
	}
	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/disable", map[string]any{"password": "Password123"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: expected 200, got %d", resp.StatusCode)
	}

	if n := storage.updateUserCalls.Load(); n != 0 {
		t.Errorf("expected no UpdateUser call, got %d", n)
	}
	u, _ := storage.MemoryStorage.GetUserByID(aliceID(t, storage))
	if u.TOTPEnabled || u.TOTPSecret != nil || u.BackupCodeHashes != nil {
		t.Errorf("ClearTOTP left state behind: %+v", u)
	}
}

func TestMemoryStorage_UpdateUserKeepsSecurityFields(t *testing.T) {
	storage := NewMemoryStorage()
	name := "alice"
	id := uuid.New()
	if err := storage.CreateUser(&User{ID: id, Username: &name, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetTOTP(id, "SECRET", []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ConsumeTOTPAttempt(id, 5); err != nil {
		t.Fatal(err)
	}

	stale, _ := storage.GetUserByID(id)
	other := "OTHER"
	stale.TOTPSecret = &other
	stale.TOTPEnabled = false
	stale.TOTPEnrolledAt = nil
	stale.BackupCodeHashes = []string{"h1", "h2", "h3"}
	stale.TOTPFailedAttempts = 0
	stale.PasswordHash = "y"
	if err := storage.UpdateUser(stale); err != nil {
		t.Fatal(err)
	}

	got, _ := storage.GetUserByID(id)
	if got.PasswordHash != "y" {
		t.Errorf("profile field not written: %q", got.PasswordHash)
	}
	if got.TOTPSecret == nil || *got.TOTPSecret != "SECRET" || !got.TOTPEnabled || got.TOTPEnrolledAt == nil ||
		len(got.BackupCodeHashes) != 2 || got.TOTPFailedAttempts != 1 {
		t.Errorf("UpdateUser changed security fields: %+v", got)
	}
}

func TestMemoryStorage_ConsumeTOTPAttempt(t *testing.T) {
	storage := NewMemoryStorage()
	id := uuid.New()
	storage.CreateUser(&User{ID: id, PasswordHash: "x"})

	for want := 2; want >= 0; want-- {
		got, err := storage.ConsumeTOTPAttempt(id, 3)
		if err != nil || got != want {
			t.Fatalf("expected remaining %d, got %d (err %v)", want, got, err)
		}
	}
	if _, err := storage.ConsumeTOTPAttempt(id, 3); err != ErrTFAAttemptsExhausted {
		t.Fatalf("expected ErrTFAAttemptsExhausted, got %v", err)
	}
	if err := storage.ResetTOTPAttempts(id); err != nil {
		t.Fatal(err)
	}
	if got, err := storage.ConsumeTOTPAttempt(id, 3); err != nil || got != 2 {
		t.Fatalf("after reset: expected 2, got %d (err %v)", got, err)
	}
	if _, err := storage.ConsumeTOTPAttempt(uuid.New(), 3); err != ErrUserNotFound {
		t.Fatalf("unknown user: expected ErrUserNotFound, got %v", err)
	}
}

// The failure that spends the last attempt ends the pending session.
func TestTFA_LastFailedAttemptEndsPendingSession(t *testing.T) {
	storage, server := setupSpyServer(t, tfaSettings())
	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)

	client := loginPending(t, server.URL)
	for i := range 5 { // the default MaxVerifyAttempts
		if status, errCode := verifyCodeError(t, client, server.URL, "000000", false); errCode != "invalid_tfa_code" {
			t.Fatalf("wrong code #%d: got %d %q", i, status, errCode)
		}
	}
	assertPendingSessionEnded(t, storage, client, server.URL, secret)
}

// A backup code that matches the hashes the handler read is refused when the
// storage reports another request consumed it first.
func TestTFA_BackupCodeLostRaceIsRefused(t *testing.T) {
	storage, server := setupSpyServer(t, tfaSettings())
	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	_, codes := enrollTFA(t, setup, server.URL)

	client := loginPending(t, server.URL)
	storage.loseBackupCodeRace.Store(true)
	if got := verifyCode(t, client, server.URL, codes[0], true); got != http.StatusUnauthorized {
		t.Fatalf("backup code consumed by a racing request: expected 401, got %d", got)
	}
}

func TestMemoryStorage_SetAndClearTOTPResetAttempts(t *testing.T) {
	storage := NewMemoryStorage()
	id := uuid.New()
	storage.CreateUser(&User{ID: id, PasswordHash: "x"})

	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"SetTOTP", func() error { return storage.SetTOTP(id, "S", []string{"h"}) }},
		{"ClearTOTP", func() error { return storage.ClearTOTP(id) }},
	} {
		if _, err := storage.ConsumeTOTPAttempt(id, 5); err != nil {
			t.Fatal(err)
		}
		if err := step.fn(); err != nil {
			t.Fatal(err)
		}
		if u, _ := storage.GetUserByID(id); u.TOTPFailedAttempts != 0 {
			t.Errorf("%s: expected counter 0, got %d", step.name, u.TOTPFailedAttempts)
		}
	}
}

func TestMemoryStorage_ReturnsIndependentCopies(t *testing.T) {
	storage := NewMemoryStorage()
	id := uuid.New()
	name, email := "alice", "alice@example.com"
	storage.CreateUser(&User{ID: id, Username: &name, Email: &email, PasswordHash: "x"})
	storage.SetTOTP(id, "S", []string{"h"})

	u, _ := storage.GetUserByID(id)
	*u.Username = "mallory"
	*u.Email = "mallory@example.com"
	*u.TOTPSecret = "X"
	*u.TOTPEnrolledAt = time.Time{}
	u.BackupCodeHashes[0] = "x"

	got, _ := storage.GetUserByID(id)
	if *got.Username != "alice" || *got.Email != "alice@example.com" || *got.TOTPSecret != "S" ||
		got.TOTPEnrolledAt.IsZero() || got.BackupCodeHashes[0] != "h" {
		t.Errorf("stored user changed through a returned copy: %+v", got)
	}
	if name != "alice" {
		t.Error("stored user shares the caller's Username pointer")
	}
}
