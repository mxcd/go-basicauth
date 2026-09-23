package basicauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// userContextKey is a custom type for context keys to avoid collisions
type userContextKey struct{}

// testUserKey is the context key used in tests
var testUserKey = userContextKey{}

// TransformedUser represents a custom user type that applications might use
type TransformedUser struct {
	ID       uuid.UUID
	Username string
	Email    string
	Role     string
}

// MockTransformerTracker tracks calls to the UserTransformer function
type MockTransformerTracker struct {
	mu    sync.Mutex
	Calls []MockTransformerCall
}

type MockTransformerCall struct {
	UserID   uuid.UUID
	Username *string
	Email    *string
}

func NewMockTransformerTracker() *MockTransformerTracker {
	return &MockTransformerTracker{
		Calls: make([]MockTransformerCall, 0),
	}
}

func (m *MockTransformerTracker) RecordCall(user *User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, MockTransformerCall{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	})
}

func (m *MockTransformerTracker) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Calls)
}

func (m *MockTransformerTracker) LastCall() *MockTransformerCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return nil
	}
	return &m.Calls[len(m.Calls)-1]
}

func (m *MockTransformerTracker) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = make([]MockTransformerCall, 0)
}

// setupTestHandlerWithUserContext creates a handler with UserKey and optional UserTransformer
func setupTestHandlerWithUserContext(userKey any, transformer func(c *gin.Context, user *User) any) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	settings := DefaultSettings()
	secretKey, _ := GenerateSessionSecretKey()
	encryptionKey, _ := GenerateSessionEncryptionKey()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.EnableRegistration = true

	handler, err := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
		UserKey:               userKey,
		UserTransformer:       transformer,
	})

	if err != nil {
		panic(err)
	}

	handler.RegisterRoutes()

	return handler, r
}

func TestUserContext_StoredAfterLogin(t *testing.T) {
	tracker := NewMockTransformerTracker()
	transformer := func(c *gin.Context, user *User) any {
		tracker.RecordCall(user)
		return &TransformedUser{
			ID:       user.ID,
			Username: ptrToString(user.Username),
			Email:    ptrToString(user.Email),
			Role:     "user",
		}
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// First register a user
	regBody := map[string]any{
		"username": "logintest",
		"email":    "login@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Reset tracker to clear registration call
	tracker.Reset()

	// Now login
	loginBody := map[string]any{
		"identifier": "logintest",
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
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify transformer was called
	if tracker.CallCount() != 1 {
		t.Errorf("expected transformer to be called once, got %d calls", tracker.CallCount())
	}

	lastCall := tracker.LastCall()
	if lastCall == nil {
		t.Fatal("expected transformer to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "logintest" {
		t.Errorf("expected username 'logintest', got %v", lastCall.Username)
	}
}

func TestUserContext_StoredAfterRegistration(t *testing.T) {
	tracker := NewMockTransformerTracker()
	transformer := func(c *gin.Context, user *User) any {
		tracker.RecordCall(user)
		return user
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register a user
	regBody := map[string]any{
		"username": "registertest",
		"email":    "register@test.com",
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
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}

	// Verify transformer was called
	if tracker.CallCount() != 1 {
		t.Errorf("expected transformer to be called once, got %d calls", tracker.CallCount())
	}

	lastCall := tracker.LastCall()
	if lastCall == nil {
		t.Fatal("expected transformer to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "registertest" {
		t.Errorf("expected username 'registertest', got %v", lastCall.Username)
	}

	if lastCall.Email == nil || *lastCall.Email != "register@test.com" {
		t.Errorf("expected email 'register@test.com', got %v", lastCall.Email)
	}

	if lastCall.UserID == uuid.Nil {
		t.Error("expected non-nil user ID")
	}
}

func TestUserContext_StoredInRequireAuthMiddleware(t *testing.T) {
	tracker := NewMockTransformerTracker()
	transformer := func(c *gin.Context, user *User) any {
		tracker.RecordCall(user)
		return user
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)

	// Add a protected route (RequireAuth is applied globally by RegisterRoutes)
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register and get session cookie
	regBody := map[string]any{
		"username": "middlewaretest",
		"email":    "middleware@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	cookies := resp.Cookies()

	// Reset tracker to clear registration call
	tracker.Reset()

	// Access protected route with session
	req, _ = http.NewRequest("GET", server.URL+"/protected", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify transformer was called
	if tracker.CallCount() != 1 {
		t.Errorf("expected transformer to be called once, got %d calls", tracker.CallCount())
	}

	lastCall := tracker.LastCall()
	if lastCall == nil {
		t.Fatal("expected transformer to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "middlewaretest" {
		t.Errorf("expected username 'middlewaretest', got %v", lastCall.Username)
	}
}

func TestUserContext_AccessibleInHandler(t *testing.T) {
	var capturedUser *TransformedUser

	transformer := func(c *gin.Context, user *User) any {
		return &TransformedUser{
			ID:       user.ID,
			Username: ptrToString(user.Username),
			Email:    ptrToString(user.Email),
			Role:     "admin",
		}
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)

	// Add a protected route that captures the user from context (RequireAuth is applied globally)
	r.GET("/protected", func(c *gin.Context) {
		if u := c.Request.Context().Value(testUserKey); u != nil {
			capturedUser = u.(*TransformedUser)
		}
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register and get session cookie
	regBody := map[string]any{
		"username": "contexttest",
		"email":    "context@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	cookies := resp.Cookies()

	// Access protected route with session
	req, _ = http.NewRequest("GET", server.URL+"/protected", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify user was captured from context
	if capturedUser == nil {
		t.Fatal("expected user to be captured from context")
	}

	if capturedUser.Username != "contexttest" {
		t.Errorf("expected username 'contexttest', got %s", capturedUser.Username)
	}

	if capturedUser.Role != "admin" {
		t.Errorf("expected role 'admin', got %s", capturedUser.Role)
	}
}

func TestUserContext_NotCalledOnFailedLogin(t *testing.T) {
	tracker := NewMockTransformerTracker()
	transformer := func(c *gin.Context, user *User) any {
		tracker.RecordCall(user)
		return user
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Try to login with non-existent user
	loginBody := map[string]any{
		"identifier": "nonexistent",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}

	// Verify transformer was NOT called
	if tracker.CallCount() != 0 {
		t.Errorf("expected transformer not to be called, got %d calls", tracker.CallCount())
	}
}

func TestUserContext_NotCalledOnUnauthenticatedRequest(t *testing.T) {
	tracker := NewMockTransformerTracker()
	transformer := func(c *gin.Context, user *User) any {
		tracker.RecordCall(user)
		return user
	}

	_, r := setupTestHandlerWithUserContext(testUserKey, transformer)

	// Add a protected route (RequireAuth is applied globally by RegisterRoutes)
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Access protected route without session
	req, _ := http.NewRequest("GET", server.URL+"/protected", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}

	// Verify transformer was NOT called
	if tracker.CallCount() != 0 {
		t.Errorf("expected transformer not to be called, got %d calls", tracker.CallCount())
	}
}

func TestUserContext_NilUserKeyDoesNotPanic(t *testing.T) {
	// This test verifies backward compatibility - nil UserKey should not cause panic
	_, r := setupTestHandlerWithUserContext(nil, nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register a user (should not panic)
	regBody := map[string]any{
		"username": "niltest",
		"email":    "nil@test.com",
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
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()

	// Login (should not panic)
	loginBody := map[string]any{
		"identifier": "niltest",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Access /me with session (should not panic)
	req, _ = http.NewRequest("GET", server.URL+"/auth/me", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("/me request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestUserContext_WithoutTransformer_StoresBasicAuthUser(t *testing.T) {
	var capturedUser *User

	_, r := setupTestHandlerWithUserContext(testUserKey, nil) // No transformer

	// Add a protected route that captures the user from context (RequireAuth is applied globally)
	r.GET("/protected", func(c *gin.Context) {
		if u := c.Request.Context().Value(testUserKey); u != nil {
			capturedUser = u.(*User)
		}
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register and get session cookie
	regBody := map[string]any{
		"username": "notransformer",
		"email":    "notransformer@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	cookies := resp.Cookies()

	// Access protected route with session
	req, _ = http.NewRequest("GET", server.URL+"/protected", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify basicauth.User was captured from context
	if capturedUser == nil {
		t.Fatal("expected user to be captured from context")
	}

	if capturedUser.Username == nil || *capturedUser.Username != "notransformer" {
		t.Errorf("expected username 'notransformer', got %v", capturedUser.Username)
	}

	if capturedUser.Email == nil || *capturedUser.Email != "notransformer@test.com" {
		t.Errorf("expected email 'notransformer@test.com', got %v", capturedUser.Email)
	}
}

// Helper function to safely convert *string to string
func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
