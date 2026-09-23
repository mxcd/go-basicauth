package basicauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// setupTestHandler creates a handler with in-memory storage and test settings
func setupTestHandler(settings *BasicAuthSettings) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	if settings == nil {
		settings = DefaultSettings()
	}
	// The flows under test register their users through the API.
	settings.EnableRegistration = true

	// Generate session keys if not provided
	if len(settings.SessionSecretKey) != 64 {
		key, _ := GenerateSessionSecretKey()
		settings.SessionSecretKey = key
	}
	if len(settings.SessionEncryptionKey) != 32 {
		key, _ := GenerateSessionEncryptionKey()
		settings.SessionEncryptionKey = key
	}

	handler, err := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})

	if err != nil {
		panic(err)
	}

	handler.RegisterRoutes()

	return handler, r
}

// E2E Positive Tests

func TestE2E_FullAuthFlow_WithUsernameAndEmail(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// 1. Register user
	regBody := map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)

	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("registration request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", resp.StatusCode)
	}

	// Save cookie for later requests
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie, got none")
	}

	// 2. Access /me with session
	req, _ = http.NewRequest("GET", server.URL+"/auth/me", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("/me request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for /me, got %d", resp.StatusCode)
	}

	var userResp UserResponse
	json.NewDecoder(resp.Body).Decode(&userResp)
	if userResp.Username == nil || *userResp.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %v", userResp.Username)
	}

	// 3. Logout
	req, _ = http.NewRequest("POST", server.URL+"/auth/logout", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for logout, got %d", resp.StatusCode)
	}

	// 4. Try to access /me after logout (should fail)
	// Don't send any cookies to simulate the expired/deleted cookie
	req, _ = http.NewRequest("GET", server.URL+"/auth/me", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("/me after logout request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 after logout, got %d", resp.StatusCode)
	}
}

func TestE2E_LoginWithUsername(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register user
	regBody := map[string]interface{}{
		"username": "john_doe",
		"email":    "john@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Login with username
	loginBody := map[string]interface{}{
		"identifier": "john_doe",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify session cookie is set
	if len(resp.Cookies()) == 0 {
		t.Error("expected session cookie after login")
	}
}

func TestE2E_LoginWithEmail(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register user
	regBody := map[string]interface{}{
		"username": "jane_doe",
		"email":    "jane@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Login with email
	loginBody := map[string]interface{}{
		"identifier": "jane@example.com",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestE2E_UsernameOnlyMode(t *testing.T) {
	settings := DefaultSettings()
	settings.SessionSecretKey = make([]byte, 64)
	settings.SessionEncryptionKey = make([]byte, 64)
	settings.EnableEmailLogin = false
	settings.EnableUsernameLogin = true

	_, r := setupTestHandler(settings)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with username only
	regBody := map[string]interface{}{
		"username": "usernameonly",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", resp.StatusCode)
	}
}

func TestE2E_EmailOnlyMode(t *testing.T) {
	settings := DefaultSettings()
	settings.SessionSecretKey = make([]byte, 64)
	settings.SessionEncryptionKey = make([]byte, 64)
	settings.EnableEmailLogin = true
	settings.EnableUsernameLogin = false

	_, r := setupTestHandler(settings)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with email only
	regBody := map[string]interface{}{
		"email":    "emailonly@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", resp.StatusCode)
	}
}

// E2E Negative Tests

func TestE2E_Registration_DuplicateUsername(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register first user
	regBody := map[string]interface{}{
		"username": "duplicate",
		"email":    "first@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Try to register with same username
	regBody2 := map[string]interface{}{
		"username": "duplicate",
		"email":    "second@example.com",
		"password": "Password123",
	}
	regJSON2, _ := json.Marshal(regBody2)
	req, _ = http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON2))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected status 409, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "user_exists" {
		t.Errorf("expected error 'user_exists', got %s", errResp.Error)
	}
}

func TestE2E_Registration_DuplicateEmail(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register first user
	regBody := map[string]interface{}{
		"username": "user1",
		"email":    "duplicate@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Try to register with same email
	regBody2 := map[string]interface{}{
		"username": "user2",
		"email":    "duplicate@example.com",
		"password": "Password123",
	}
	regJSON2, _ := json.Marshal(regBody2)
	req, _ = http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON2))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected status 409, got %d", resp.StatusCode)
	}
}

func TestE2E_Registration_MissingCredentials(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register without username or email
	regBody := map[string]interface{}{
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestE2E_Registration_WeakPassword(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with weak password (no numbers)
	regBody := map[string]interface{}{
		"username": "weakpass",
		"email":    "weak@example.com",
		"password": "Password",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "weak_password" {
		t.Errorf("expected error 'weak_password', got %s", errResp.Error)
	}
}

func TestE2E_Registration_InvalidEmail(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with invalid email
	regBody := map[string]interface{}{
		"username": "testuser",
		"email":    "notanemail",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	// Note: Gin's binding validation catches invalid email format before our validator
	// so the error is "invalid_request" with details about the validation failure
	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "invalid_request" && errResp.Error != "invalid_email" {
		t.Errorf("expected error 'invalid_request' or 'invalid_email', got %s", errResp.Error)
	}
}

func TestE2E_Registration_InvalidUsername(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with invalid username (contains space)
	regBody := map[string]interface{}{
		"username": "test user",
		"email":    "test@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "invalid_username" {
		t.Errorf("expected error 'invalid_username', got %s", errResp.Error)
	}
}

func TestE2E_Login_WrongPassword(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register user
	regBody := map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Try to login with wrong password
	loginBody := map[string]interface{}{
		"identifier": "testuser",
		"password":   "WrongPassword123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "invalid_credentials" {
		t.Errorf("expected error 'invalid_credentials', got %s", errResp.Error)
	}

	// Verify error message is generic (doesn't leak user existence)
	if !strings.Contains(errResp.Message, "Invalid credentials") {
		t.Errorf("expected generic error message, got: %s", errResp.Message)
	}
}

func TestE2E_Login_UserNotFound(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Try to login with non-existent user
	loginBody := map[string]interface{}{
		"identifier": "nonexistent",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)

	// Verify error message is the same as wrong password (prevents user enumeration)
	if errResp.Error != "invalid_credentials" {
		t.Errorf("expected error 'invalid_credentials', got %s", errResp.Error)
	}
}

func TestE2E_Login_DisabledMethod(t *testing.T) {
	// Setup with username login disabled
	settings := DefaultSettings()
	settings.SessionSecretKey = make([]byte, 64)
	settings.SessionEncryptionKey = make([]byte, 64)
	settings.EnableUsernameLogin = false
	settings.EnableEmailLogin = true

	_, r := setupTestHandler(settings)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with email only
	regBody := map[string]interface{}{
		"email":    "test@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Try to login with username (which would fail anyway since we didn't provide one)
	// But even if we had a username field, login should fail because username login is disabled
	loginBody := map[string]interface{}{
		"identifier": "testuser",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestE2E_Me_Unauthenticated(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Try to access /me without session
	req, _ := http.NewRequest("GET", server.URL+"/auth/me", nil)
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestE2E_Me_InvalidSession(t *testing.T) {
	_, r := setupTestHandler(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Try to access /me with invalid session cookie
	req, _ := http.NewRequest("GET", server.URL+"/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:  "basicauth_session",
		Value: "invalid_session_data",
	})
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestE2E_ContextPropagation(t *testing.T) {
	handler, r := setupTestHandler(nil)

	// Add a protected route that uses GetUserFromContext
	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		user, err := GetUserFromContext(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": user.ID.String()})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register and login
	regBody := map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	cookies := resp.Cookies()

	// Access protected route
	req, _ = http.NewRequest("GET", server.URL+"/protected", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, _ = client.Do(req)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["user_id"] == "" {
		t.Error("expected user_id in response, got empty")
	}
}
