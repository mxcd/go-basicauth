package basicauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func tfaSettings() *BasicAuthSettings {
	s := DefaultSettings()
	s.CookieSecure = false
	s.EnableTFA = true
	s.TFA.Issuer = "TestApp"
	return s
}

func clientWithJar(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func registerAndLogin(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp := doJSON(t, client, "POST", baseURL+"/auth/register", map[string]any{
		"username": "alice",
		"password": "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
}

func enrollTFA(t *testing.T, client *http.Client, baseURL string) (secret string, backupCodes []string) {
	t.Helper()

	resp := doJSON(t, client, "POST", baseURL+"/auth/tfa/setup", nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("setup: expected 200, got %d: %s", resp.StatusCode, string(b))
	}
	var setup TFASetupResponse
	json.NewDecoder(resp.Body).Decode(&setup)
	resp.Body.Close()

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	resp = doJSON(t, client, "POST", baseURL+"/auth/tfa/enable", map[string]any{
		"code":     code,
		"password": "Password123",
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("enable: expected 200, got %d: %s", resp.StatusCode, string(b))
	}
	var enable TFAEnableResponse
	json.NewDecoder(resp.Body).Decode(&enable)
	resp.Body.Close()

	return setup.Secret, enable.BackupCodes
}

func TestTFA_EnrollmentHappyPath(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	_, codes := enrollTFA(t, client, server.URL)
	if len(codes) != 10 {
		t.Errorf("expected 10 backup codes, got %d", len(codes))
	}
	for _, c := range codes {
		if len(c) != 10 {
			t.Errorf("expected 10-char backup codes, got %q (len %d)", c, len(c))
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Errorf("default backup code should be digits only, got %q", c)
				break
			}
		}
	}
}

func TestTFA_EnrollmentWrongCode(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d", resp.StatusCode)
	}

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/enable", map[string]any{
		"code":     "000000",
		"password": "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong code, got %d", resp.StatusCode)
	}
}

func TestTFA_LoginRequiresSecondFactor(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	secret, _ := enrollTFA(t, client, server.URL)

	// logout so we can re-login
	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	// fresh client (simulates new browser session)
	client = clientWithJar(t)

	// password-only login → 202 tfaRequired
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 202 on TFA-gated login, got %d: %s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// /me should still be unauthorized
	resp = doJSON(t, client, "GET", server.URL+"/auth/me", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected /me unauthorized during pending TFA, got %d", resp.StatusCode)
	}

	// submit valid TOTP → promoted to full session
	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("verify: expected 200, got %d: %s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// /me now works
	resp = doJSON(t, client, "GET", server.URL+"/auth/me", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected /me OK after verify, got %d", resp.StatusCode)
	}
}

func TestTFA_VerifyWrongCode(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	enrollTFA(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "000000"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on bad code, got %d", resp.StatusCode)
	}
}

func TestTFA_BackupCodeConsumption(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	_, codes := enrollTFA(t, client, server.URL)
	if len(codes) == 0 {
		t.Fatal("no backup codes issued")
	}
	code := codes[0]

	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	// First use of backup code succeeds
	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{
		"code":         code,
		"isBackupCode": true,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup code verify: expected 200, got %d", resp.StatusCode)
	}

	// Re-use of same code fails
	resp = doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{
		"code":         code,
		"isBackupCode": true,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on reused backup code, got %d", resp.StatusCode)
	}
}

func TestTFA_DisableRequiresPassword(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	enrollTFA(t, client, server.URL)

	// Wrong password → 401
	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/disable", map[string]any{"password": "WrongPass123"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong password, got %d", resp.StatusCode)
	}

	// Right password → 200
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/disable", map[string]any{"password": "Password123"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on correct password, got %d", resp.StatusCode)
	}

	// Subsequent login no longer requires TFA
	resp = doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected normal 200 login after disable, got %d", resp.StatusCode)
	}
}

func TestTFA_DisabledInSettings(t *testing.T) {
	// Default settings: EnableTFA is false. CookieSecure must be off so the
	// session cookie survives the plain-HTTP httptest server.
	s := DefaultSettings()
	s.CookieSecure = false
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	for _, path := range []string{"/auth/tfa/setup", "/auth/tfa/enable", "/auth/tfa/disable", "/auth/tfa/verify"} {
		resp := doJSON(t, client, "POST", server.URL+path, map[string]any{})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: expected 404 when TFA disabled, got %d", path, resp.StatusCode)
		}
	}
}

// attemptVerifyAtOffset runs a fresh password-login and submits a code generated
// at (now + offset). Returns the verify response status.
func attemptVerifyAtOffset(t *testing.T, serverURL, secret string, offset time.Duration) int {
	t.Helper()
	client := clientWithJar(t)
	resp := doJSON(t, client, "POST", serverURL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	code, err := totp.GenerateCodeCustom(secret, time.Now().Add(offset), totp.ValidateOpts{
		Period: 30,
		Digits: otp.DigitsSix,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	resp = doJSON(t, client, "POST", serverURL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	return resp.StatusCode
}

func TestTFA_SkewWindow(t *testing.T) {
	// SkewWindows=1 → ±30s window accepted, ±60s and beyond rejected.
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	cases := []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"current window", 0, http.StatusOK},
		{"previous window (-30s)", -30 * time.Second, http.StatusOK},
		{"next window (+30s)", 30 * time.Second, http.StatusOK},
		{"two windows back (-60s)", -60 * time.Second, http.StatusUnauthorized},
		{"two windows forward (+60s)", 60 * time.Second, http.StatusUnauthorized},
		{"far past (-5m)", -5 * time.Minute, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attemptVerifyAtOffset(t, server.URL, secret, tc.offset)
			if got != tc.want {
				t.Errorf("offset %v: expected %d, got %d", tc.offset, tc.want, got)
			}
		})
	}
}

func TestTFA_StrictSkewRejectsAdjacentWindow(t *testing.T) {
	// SkewWindows=0 → only the exact current window is accepted.
	s := tfaSettings()
	s.TFA.SkewWindows = 0
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	if got := attemptVerifyAtOffset(t, server.URL, secret, -30*time.Second); got != http.StatusUnauthorized {
		t.Errorf("strict skew should reject -30s code, got %d", got)
	}
	if got := attemptVerifyAtOffset(t, server.URL, secret, 0); got != http.StatusOK {
		t.Errorf("strict skew should accept current code, got %d", got)
	}
}

func TestTFA_SetupRequiresAuth(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated setup, got %d", resp.StatusCode)
	}
}

func TestTFA_EnableWithoutSetup(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/enable", map[string]any{
		"code":     "123456",
		"password": "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for enable without prior setup, got %d", resp.StatusCode)
	}
}

func TestTFA_SetupRejectedWhenAlreadyEnabled(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	enrollTFA(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 on setup while enabled, got %d", resp.StatusCode)
	}
}

func TestTFA_DisableWhenNotEnabled(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/disable", map[string]any{"password": "Password123"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 disabling when not enabled, got %d", resp.StatusCode)
	}
}

func TestTFA_VerifyWithoutPendingSession(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "123456"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for verify with no pending session, got %d", resp.StatusCode)
	}
}

func TestTFA_CustomBackupCodeAlphabetAndLength(t *testing.T) {
	s := tfaSettings()
	s.TFA.BackupCodeAlphabet = "ABCDEF"
	s.TFA.BackupCodeLength = 16
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	_, codes := enrollTFA(t, client, server.URL)

	// Alphabet is normalized to lowercase at generation time so issued codes
	// and their hashes agree with the case-insensitive verify path.
	for _, c := range codes {
		if len(c) != 16 {
			t.Errorf("expected length 16, got %q (len %d)", c, len(c))
		}
		if strings.Trim(c, "abcdef") != "" {
			t.Errorf("expected only alphabet chars, got %q", c)
		}
	}

	// Regression for the case-mismatch bug: a custom alphabet must actually
	// verify round-trip, not just look right.
	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{
		"code":         codes[0],
		"isBackupCode": true,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("backup code from custom alphabet failed to verify: expected 200, got %d", resp.StatusCode)
	}
}

func TestTFA_CustomBackupCodeCount(t *testing.T) {
	s := tfaSettings()
	s.TFA.BackupCodeCount = 3
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	_, codes := enrollTFA(t, client, server.URL)

	if len(codes) != 3 {
		t.Errorf("expected 3 backup codes, got %d", len(codes))
	}
}

func TestTFA_ZeroBackupCodesDisablesBackupVerify(t *testing.T) {
	s := tfaSettings()
	s.TFA.BackupCodeCount = 0
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	_, codes := enrollTFA(t, client, server.URL)
	if len(codes) != 0 {
		t.Errorf("expected no backup codes, got %d", len(codes))
	}

	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{
		"code":         "abcdef0123",
		"isBackupCode": true,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 when backup codes disabled, got %d", resp.StatusCode)
	}
}

func TestTFA_PendingSessionExpires(t *testing.T) {
	s := tfaSettings()
	s.TFA.PendingSessionTTL = 1 * time.Second
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client := clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("login: expected 202, got %d", resp.StatusCode)
	}

	// Wait past the pending session TTL; the cookie jar will drop the expired cookie.
	time.Sleep(1500 * time.Millisecond)

	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 after pending session expiry, got %d", resp.StatusCode)
	}
}

func TestTFA_SetupUsesCustomAccountLabel(t *testing.T) {
	s := tfaSettings()
	s.TFA.AccountLabel = func(u *User) string { return "custom:" + u.ID.String() }
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	var setup TFASetupResponse
	json.NewDecoder(resp.Body).Decode(&setup)
	resp.Body.Close()

	if !strings.HasPrefix(setup.AccountName, "custom:") {
		t.Errorf("expected custom account label, got %q", setup.AccountName)
	}
}

func TestTFA_SetupFallsBackToEmail(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	resp := doJSON(t, client, "POST", server.URL+"/auth/register", map[string]any{
		"email":    "bob@example.com",
		"password": "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}

	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	var setup TFASetupResponse
	json.NewDecoder(resp.Body).Decode(&setup)
	resp.Body.Close()

	if setup.AccountName != "bob@example.com" {
		t.Errorf("expected account label to fall back to email, got %q", setup.AccountName)
	}
}

func TestTFA_SetupFailsWithoutIssuer(t *testing.T) {
	s := tfaSettings()
	s.TFA.Issuer = ""
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/setup", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 when issuer is empty, got %d", resp.StatusCode)
	}
}

func TestTFA_RequiredBlocksUnenrolledUserOnProtectedRoute(t *testing.T) {
	s := tfaSettings()
	s.TFA.Required = true
	h, r := setupTestHandler(s)
	_ = h
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	// Bypass routes still work for an unenrolled user.
	for _, path := range []string{"/auth/me", "/auth/tfa/setup"} {
		resp := doJSON(t, client, "POST", server.URL+path, nil)
		if path == "/auth/me" {
			resp = doJSON(t, client, "GET", server.URL+path, nil)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("%s: should be reachable during enrollment, got 403", path)
		}
	}

	// Application routes are blocked with a structured error.
	resp := doJSON(t, client, "GET", server.URL+"/protected", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on protected route, got %d", resp.StatusCode)
	}
	var errResp ErrorResponse
	json.Unmarshal(body, &errResp)
	if errResp.Error != "tfa_setup_required" {
		t.Errorf("expected error code tfa_setup_required, got %q", errResp.Error)
	}

	// Completing enrollment unblocks the route.
	enrollTFA(t, client, server.URL)
	resp = doJSON(t, client, "GET", server.URL+"/protected", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on protected route after enrollment, got %d", resp.StatusCode)
	}
}

func TestTFA_RequiredDoesNotAffectEnrolledUsers(t *testing.T) {
	s := tfaSettings()
	s.TFA.Required = true
	_, r := setupTestHandler(s)
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)
	secret, _ := enrollTFA(t, client, server.URL)
	resp := doJSON(t, client, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	// Full login + verify flow, then hit /protected
	client = clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()

	resp = doJSON(t, client, "GET", server.URL+"/protected", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on protected route for enrolled user, got %d", resp.StatusCode)
	}
}

func TestTFA_RequiredOffDoesNotBlock(t *testing.T) {
	// Default: TFA.Required is false. Unenrolled users reach protected routes.
	s := tfaSettings()
	_, r := setupTestHandler(s)
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	server := httptest.NewServer(r)
	defer server.Close()

	client := clientWithJar(t)
	registerAndLogin(t, client, server.URL)

	resp := doJSON(t, client, "GET", server.URL+"/protected", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 when Required=false, got %d", resp.StatusCode)
	}
}

func TestTFA_VerifyAttemptLimit(t *testing.T) {
	s := tfaSettings()
	s.TFA.MaxVerifyAttempts = 3
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client := clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("login: expected 202, got %d", resp.StatusCode)
	}

	// 3 wrong attempts exhaust the budget
	for i := range 3 {
		resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "000000"})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("wrong attempt %d: expected 401, got %d", i+1, resp.StatusCode)
		}
	}

	// Now the correct code should no longer work — pending session was invalidated
	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 after exhausting attempts, got %d", resp.StatusCode)
	}
}

func TestTFA_VerifyStillSucceedsWithinAttemptBudget(t *testing.T) {
	s := tfaSettings()
	s.TFA.MaxVerifyAttempts = 3
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	client := clientWithJar(t)
	resp = doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	// Two wrong attempts, then a correct one — should still succeed
	for range 2 {
		resp := doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "000000"})
		resp.Body.Close()
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 when within attempt budget, got %d", resp.StatusCode)
	}
}

// TestTFA_AttemptBudgetSurvivesCookieReplay asserts that the MaxVerifyAttempts
// counter is per-user (server-side), not per-cookie. A fresh cookie replay
// cannot reset the budget — otherwise an attacker with a captured pending
// cookie could guess TOTP indefinitely.
func TestTFA_AttemptBudgetSurvivesCookieReplay(t *testing.T) {
	s := tfaSettings()
	s.TFA.MaxVerifyAttempts = 3
	_, r := setupTestHandler(s)
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	secret, _ := enrollTFA(t, setup, server.URL)
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	// Legitimate client logs in to get a pending cookie.
	clientA := clientWithJar(t)
	resp = doJSON(t, clientA, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()

	// Snapshot the pending cookie — this is the "captured" cookie the attacker gets.
	serverURL, _ := url.Parse(server.URL)
	capturedCookies := clientA.Jar.Cookies(serverURL)

	// Burn 2 wrong attempts on clientA (counter → 2).
	for range 2 {
		resp := doJSON(t, clientA, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "000000"})
		resp.Body.Close()
	}

	// Attacker replays the captured pending cookie. If the counter lived in the
	// cookie, the attacker would see attempts=0 here. With the server-side
	// counter, the attacker observes the shared budget: one wrong guess takes
	// counter to 3 and exhausts the budget for everyone using that user ID.
	attacker, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	attacker.SetCookies(serverURL, capturedCookies)
	clientB := &http.Client{Jar: attacker}

	resp = doJSON(t, clientB, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": "000000"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on attacker's wrong guess, got %d", resp.StatusCode)
	}

	// Budget is now exhausted. Even the legitimate client's correct code is
	// rejected — the user must log in again to earn a fresh budget.
	code, _ := totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, clientA, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 after shared budget exhaustion, got %d", resp.StatusCode)
	}

	// A fresh password login resets the counter (defense against accidental lockouts).
	clientC := clientWithJar(t)
	resp = doJSON(t, clientC, "POST", server.URL+"/auth/login", map[string]any{
		"identifier": "alice",
		"password":   "Password123",
	})
	resp.Body.Close()
	code, _ = totp.GenerateCode(secret, time.Now())
	resp = doJSON(t, clientC, "POST", server.URL+"/auth/tfa/verify", map[string]any{"code": code})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after re-login resets budget, got %d", resp.StatusCode)
	}
}

func TestMemoryStorage_ConsumeBackupCodeHashIsAtomic(t *testing.T) {
	storage := NewMemoryStorage()
	u := "alice"
	user := &User{
		ID:               uuid.New(),
		Username:         &u,
		PasswordHash:     "x",
		BackupCodeHashes: []string{"h1", "h2", "h3"},
	}
	if err := storage.CreateUser(user); err != nil {
		t.Fatalf("create: %v", err)
	}

	const concurrent = 32
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := storage.ConsumeBackupCodeHash(user.ID, "h1")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("expected exactly 1 consumption of h1, got %d", got)
	}

	stored, _ := storage.GetUserByID(user.ID)
	if len(stored.BackupCodeHashes) != 2 {
		t.Errorf("expected 2 remaining hashes, got %d", len(stored.BackupCodeHashes))
	}
}

func TestMemoryStorage_ConsumeBackupCodeHashMissing(t *testing.T) {
	storage := NewMemoryStorage()
	u := "alice"
	user := &User{
		ID:               uuid.New(),
		Username:         &u,
		PasswordHash:     "x",
		BackupCodeHashes: []string{"h1"},
	}
	storage.CreateUser(user)

	ok, err := storage.ConsumeBackupCodeHash(user.ID, "missing")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for missing hash")
	}

	ok, err = storage.ConsumeBackupCodeHash(uuid.New(), "h1")
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
	if ok {
		t.Error("expected ok=false for unknown user")
	}
}

func TestTFA_MultipleBackupCodesUsableIndependently(t *testing.T) {
	_, r := setupTestHandler(tfaSettings())
	server := httptest.NewServer(r)
	defer server.Close()

	setup := clientWithJar(t)
	registerAndLogin(t, setup, server.URL)
	_, codes := enrollTFA(t, setup, server.URL)
	if len(codes) < 2 {
		t.Fatalf("need at least 2 backup codes, got %d", len(codes))
	}
	resp := doJSON(t, setup, "POST", server.URL+"/auth/logout", nil)
	resp.Body.Close()

	for i, code := range codes[:2] {
		client := clientWithJar(t)
		resp := doJSON(t, client, "POST", server.URL+"/auth/login", map[string]any{
			"identifier": "alice",
			"password":   "Password123",
		})
		resp.Body.Close()

		resp = doJSON(t, client, "POST", server.URL+"/auth/tfa/verify", map[string]any{
			"code":         code,
			"isBackupCode": true,
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("backup code #%d: expected 200, got %d", i, resp.StatusCode)
		}
	}
}
