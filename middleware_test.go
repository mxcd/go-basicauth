package basicauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupTestMiddleware(publicPaths []PublicPath) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	settings := DefaultSettings()
	secretKey, _ := GenerateSessionSecretKey()
	encryptionKey, _ := GenerateSessionEncryptionKey()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.PublicPaths = publicPaths

	handler, _ := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})

	handler.RegisterRoutes()

	return handler, r
}

func TestRequireAuth_PublicPathExact(t *testing.T) {
	publicPaths := []PublicPath{
		{Type: PublicPathExact, Path: "/public"},
		{Type: PublicPathExact, Path: "/api/health"},
	}

	handler, r := setupTestMiddleware(publicPaths)

	r.GET("/public", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public"})
	})

	r.GET("/public/nested", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "nested"})
	})

	r.GET("/api/health", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	tests := []struct {
		path         string
		expectStatus int
		expectPublic bool
		description  string
	}{
		{"/public", 200, true, "exact match should allow access"},
		{"/public/nested", 401, false, "exact match should not match nested path"},
		{"/api/health", 200, true, "exact match should allow access"},
		{"/protected", 401, false, "non-public path should require auth"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_PublicPathPrefix(t *testing.T) {
	publicPaths := []PublicPath{
		{Type: PublicPathPrefix, Path: "/public"},
		{Type: PublicPathPrefix, Path: "/api/v1/health"},
	}

	handler, r := setupTestMiddleware(publicPaths)

	r.GET("/public", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public"})
	})

	r.GET("/public/nested", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "nested"})
	})

	r.GET("/public/nested/deep", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "deep"})
	})

	r.GET("/api/v1/health", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/api/v1/health/check", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/public", 200, "prefix match should allow access"},
		{"/public/nested", 200, "prefix match should allow nested path"},
		{"/public/nested/deep", 200, "prefix match should allow deeply nested path"},
		{"/api/v1/health", 200, "prefix match should allow access"},
		{"/api/v1/health/check", 200, "prefix match should allow nested path"},
		{"/protected", 401, "non-public path should require auth"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_MixedPublicPaths(t *testing.T) {
	publicPaths := []PublicPath{
		{Type: PublicPathExact, Path: "/exact"},
		{Type: PublicPathPrefix, Path: "/prefix"},
	}

	handler, r := setupTestMiddleware(publicPaths)

	r.GET("/exact", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "exact"})
	})

	r.GET("/exact/nested", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "exact nested"})
	})

	r.GET("/prefix", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "prefix"})
	})

	r.GET("/prefix/nested", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "prefix nested"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/exact", 200, "exact match should work"},
		{"/exact/nested", 401, "exact should not match nested"},
		{"/prefix", 200, "prefix match should work"},
		{"/prefix/nested", 200, "prefix should match nested"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_NoPublicPaths(t *testing.T) {
	handler, r := setupTestMiddleware([]PublicPath{})

	r.GET("/anything", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "anything"})
	})

	req := httptest.NewRequest("GET", "/anything", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 when no public paths configured, got %d", w.Code)
	}
}

func setupTestMiddlewareWithRules(pathRules []PathRule) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	settings := DefaultSettings()
	secretKey, _ := GenerateSessionSecretKey()
	encryptionKey, _ := GenerateSessionEncryptionKey()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.PathRules = pathRules

	handler, _ := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})

	handler.RegisterRoutes()

	return handler, r
}

func TestRequireAuth_PathPrecedence(t *testing.T) {
	pathRules := []PathRule{
		{Type: PublicPathPrefix, Path: "/", Access: PathAccessPublic},
		{Type: PublicPathPrefix, Path: "/api", Access: PathAccessPrivate},
		{Type: PublicPathExact, Path: "/api/v1/health", Access: PathAccessPublic},
	}

	handler, r := setupTestMiddlewareWithRules(pathRules)

	r.GET("/", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "root"})
	})

	r.GET("/about", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "about"})
	})

	r.GET("/api/users", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "users"})
	})

	r.GET("/api/v1/health", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/api/v1/users", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "v1 users"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/", 200, "root should be public (matches / prefix)"},
		{"/about", 200, "about should be public (matches / prefix)"},
		{"/api/users", 401, "api/users should be private (matches /api prefix, longer than /)"},
		{"/api/v1/health", 200, "api/v1/health should be public (exact match, longer than /api prefix)"},
		{"/api/v1/users", 401, "api/v1/users should be private (matches /api prefix, no exact match)"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_MultiplePrefixPrecedence(t *testing.T) {
	pathRules := []PathRule{
		{Type: PublicPathPrefix, Path: "/public", Access: PathAccessPublic},
		{Type: PublicPathPrefix, Path: "/public/admin", Access: PathAccessPrivate},
		{Type: PublicPathPrefix, Path: "/public/admin/health", Access: PathAccessPublic},
	}

	handler, r := setupTestMiddlewareWithRules(pathRules)

	r.GET("/public/docs", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "docs"})
	})

	r.GET("/public/admin/users", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "users"})
	})

	r.GET("/public/admin/health/status", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/public/docs", 200, "should match /public prefix (public)"},
		{"/public/admin/users", 401, "should match /public/admin prefix (private, longer than /public)"},
		{"/public/admin/health/status", 200, "should match /public/admin/health prefix (public, longest match)"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_ExactVsPrefixPrecedence(t *testing.T) {
	pathRules := []PathRule{
		{Type: PublicPathPrefix, Path: "/api", Access: PathAccessPublic},
		{Type: PublicPathExact, Path: "/api/admin", Access: PathAccessPrivate},
	}

	handler, r := setupTestMiddlewareWithRules(pathRules)

	r.GET("/api/users", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "users"})
	})

	r.GET("/api/admin", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "admin"})
	})

	r.GET("/api/admin/settings", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "settings"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/api/users", 200, "should match /api prefix (public)"},
		{"/api/admin", 401, "should match /api/admin exact (private, same length as prefix but exact takes precedence)"},
		{"/api/admin/settings", 200, "should match /api prefix (public, exact doesn't match)"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func TestRequireAuth_BackwardCompatibilityWithPublicPaths(t *testing.T) {
	publicPaths := []PublicPath{
		{Type: PublicPathExact, Path: "/health"},
	}

	handler, r := setupTestMiddleware(publicPaths)

	r.GET("/health", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	tests := []struct {
		path         string
		expectStatus int
		description  string
	}{
		{"/health", 200, "PublicPaths should still work (backward compatibility)"},
		{"/protected", 401, "non-public path should require auth"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for path %s", tt.expectStatus, w.Code, tt.path)
			}
		})
	}
}

func setupTestMiddlewareWithCustomBaseUrl(baseUrl string, publicPaths []PublicPath) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	settings := DefaultSettings()
	secretKey, _ := GenerateSessionSecretKey()
	encryptionKey, _ := GenerateSessionEncryptionKey()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.PublicPaths = publicPaths
	settings.EnableRegistration = true

	handler, _ := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: baseUrl,
		Storage:               storage,
		Settings:              settings,
	})

	handler.RegisterRoutes()

	return handler, r
}

func TestRequireAuth_CustomBaseUrl_AuthEndpoints(t *testing.T) {
	customBaseUrl := "/api/v1/auth"
	handler, r := setupTestMiddlewareWithCustomBaseUrl(customBaseUrl, []PublicPath{})

	// Apply global middleware
	r.Use(handler.RequireAuth())

	// Add a protected endpoint
	r.GET("/api/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	tests := []struct {
		method       string
		path         string
		expectStatus int
		description  string
	}{
		{"POST", "/api/v1/auth/register", 400, "register should be public (400 = reached handler, not 401)"},
		{"POST", "/api/v1/auth/login", 400, "login should be public (400 = reached handler, not 401)"},
		{"POST", "/api/v1/auth/logout", 401, "logout should be protected"},
		{"GET", "/api/v1/auth/me", 401, "me should be protected"},
		{"GET", "/api/protected", 401, "other endpoints should be protected by default"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for %s %s", tt.expectStatus, w.Code, tt.method, tt.path)
			}
		})
	}
}

func TestRequireAuth_CustomBaseUrl_WithPublicPaths(t *testing.T) {
	customBaseUrl := "/custom/auth"
	publicPaths := []PublicPath{
		{Type: PublicPathPrefix, Path: "/public"},
	}
	handler, r := setupTestMiddlewareWithCustomBaseUrl(customBaseUrl, publicPaths)

	// Apply global middleware
	r.Use(handler.RequireAuth())

	// Add endpoints
	r.GET("/public/docs", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "docs"})
	})
	r.GET("/private/data", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "data"})
	})

	tests := []struct {
		method       string
		path         string
		expectStatus int
		description  string
	}{
		{"POST", "/custom/auth/register", 400, "register should be public with custom base url"},
		{"POST", "/custom/auth/login", 400, "login should be public with custom base url"},
		{"POST", "/custom/auth/logout", 401, "logout should be protected with custom base url"},
		{"GET", "/custom/auth/me", 401, "me should be protected with custom base url"},
		{"GET", "/public/docs", 200, "public paths should still work with custom base url"},
		{"GET", "/private/data", 401, "private paths should still require auth with custom base url"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for %s %s", tt.expectStatus, w.Code, tt.method, tt.path)
			}
		})
	}
}

func TestRequireAuth_DefaultBaseUrl_AuthEndpoints(t *testing.T) {
	// Test with empty base URL (should default to /auth)
	handler, r := setupTestMiddlewareWithCustomBaseUrl("", []PublicPath{})

	// Apply global middleware
	r.Use(handler.RequireAuth())

	tests := []struct {
		method       string
		path         string
		expectStatus int
		description  string
	}{
		{"POST", "/auth/register", 400, "register should be public with default base url"},
		{"POST", "/auth/login", 400, "login should be public with default base url"},
		{"POST", "/auth/logout", 401, "logout should be protected with default base url"},
		{"GET", "/auth/me", 401, "me should be protected with default base url"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d for %s %s", tt.expectStatus, w.Code, tt.method, tt.path)
			}
		})
	}
}

func TestRegistration_ClosedByDefault(t *testing.T) {
	if DefaultSettings().EnableRegistration {
		t.Fatal("EnableRegistration must default to false")
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	settings := DefaultSettings()
	settings.SessionSecretKey, _ = GenerateSessionSecretKey()
	settings.SessionEncryptionKey, _ = GenerateSessionEncryptionKey()
	storage := NewMemoryStorage()
	handler, err := NewHandler(&Options{Engine: r, AuthenticationBaseUrl: "/api/v1/auth", Storage: storage, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	handler.RegisterRoutes()

	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`{"username":"mallory","password":"Password123"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 with registration disabled, got %d", w.Code)
	}
	if _, err := storage.GetUserByUsername("mallory"); err != ErrUserNotFound {
		t.Errorf("no user may be created, got err=%v", err)
	}
}

func TestRegistration_OpenWhenEnabled(t *testing.T) {
	_, r := setupTestMiddlewareWithCustomBaseUrl("/api/v1/auth", nil)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`{"username":"alice","password":"Password123"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 with registration enabled, got %d", w.Code)
	}
}
