package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/go-basicauth"
)

func main() {
	// Create Gin router
	r := gin.Default()

	// Generate session keys (in production, load these from environment/config)
	secretKey, err := basicauth.GenerateSessionSecretKey()
	if err != nil {
		log.Fatal("Failed to generate secret key:", err)
	}

	encryptionKey, err := basicauth.GenerateSessionEncryptionKey()
	if err != nil {
		log.Fatal("Failed to generate encryption key:", err)
	}

	// Configure authentication settings
	settings := basicauth.DefaultSettings()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.EnableUsernameLogin = true
	settings.EnableEmailLogin = true
	settings.EnableRegistration = true // demo: open self-registration (off by default)

	// Optional: Customize settings
	// settings.CookieSecure = false // Set to false for local development without HTTPS
	// settings.PasswordRequirements.MinLength = 10

	// Create in-memory storage (in production, use a database)
	storage := basicauth.NewMemoryStorage()

	// Create authentication handler
	handler, err := basicauth.NewHandler(&basicauth.Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})

	if err != nil {
		log.Fatal("Failed to create handler:", err)
	}

	// Register authentication routes
	handler.RegisterRoutes()

	// Example: Public route
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome! Register at POST /auth/register or login at POST /auth/login",
		})
	})

	// Example: Protected route
	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		user, err := basicauth.GetUserFromContext(c)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get user from context"})
			return
		}

		c.JSON(200, gin.H{
			"message":  "This is a protected route",
			"user_id":  user.ID,
			"username": user.Username,
			"email":    user.Email,
		})
	})

	// Example: Admin route (you can add custom authorization checks)
	r.GET("/admin", handler.RequireAuth(), func(c *gin.Context) {
		user, err := basicauth.GetUserFromContext(c)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get user from context"})
			return
		}

		// Custom authorization logic
		// if !user.IsAdmin {
		//     c.JSON(403, gin.H{"error": "Forbidden"})
		//     return
		// }

		c.JSON(200, gin.H{
			"message": "Admin area",
			"user":    basicauth.ToUserResponse(user),
		})
	})

	// Start server
	log.Println("Starting server on :8080...")
	log.Println("Try these endpoints:")
	log.Println("  POST /auth/register - Register a new user")
	log.Println("  POST /auth/login    - Login")
	log.Println("  POST /auth/logout   - Logout")
	log.Println("  GET  /auth/me       - Get current user")
	log.Println("  GET  /protected     - Protected route example")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
