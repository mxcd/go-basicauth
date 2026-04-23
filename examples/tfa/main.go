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

	// Configure authentication settings with TFA enabled
	settings := basicauth.DefaultSettings()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey
	settings.CookieSecure = false // local dev over HTTP

	// Enable TFA. Issuer is required — it's the label shown in authenticator apps.
	settings.EnableTFA = true
	settings.TFA.Issuer = "BasicAuthDemo"
	settings.TFA.Required = true // every user must enroll before reaching protected routes
	// settings.TFA.BackupCodeCount = 10 // default
	// settings.TFA.SkewWindows = 1      // default, ±30s tolerance
	// settings.TFA.AccountLabel = func(u *basicauth.User) string {
	//     if u.Email != nil {
	//         return *u.Email
	//     }
	//     return u.ID.String()
	// }

	// Create in-memory storage (in production, use a database)
	storage := basicauth.NewMemoryStorage()

	handler, err := basicauth.NewHandler(&basicauth.Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
	})
	if err != nil {
		log.Fatal("Failed to create handler:", err)
	}

	handler.RegisterRoutes()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome! Register, login, then POST /auth/tfa/setup to enroll a second factor.",
		})
	})

	r.GET("/protected", func(c *gin.Context) {
		user, err := basicauth.GetUserFromContext(c)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get user from context"})
			return
		}
		// With TFA.Required enabled, this handler is only reachable when the
		// user has completed enrollment. Otherwise the middleware returns
		// 403 { "error": "tfa_setup_required" } before we get here.
		c.JSON(200, gin.H{
			"message":  "Password + TFA verified",
			"user_id":  user.ID,
			"username": user.Username,
		})
	})

	log.Println("Starting server on :8080...")
	log.Println("TFA is enforced — /protected returns 403 tfa_setup_required until enrollment is complete.")
	log.Println("Flow:")
	log.Println("  1. POST /auth/register           {username, password}")
	log.Println("  2. GET  /protected               -> 403 { error: tfa_setup_required }")
	log.Println("  3. POST /auth/tfa/setup          -> returns {secret, otpauthUrl}")
	log.Println("     Scan otpauthUrl in your authenticator app")
	log.Println("  4. POST /auth/tfa/enable         {code} -> returns {backupCodes}")
	log.Println("  5. GET  /protected               -> 200 (now allowed)")
	log.Println("  6. POST /auth/logout")
	log.Println("  7. POST /auth/login              {identifier, password} -> 202 tfaRequired")
	log.Println("  8. POST /auth/tfa/verify         {code} -> 200, full session")
	log.Println("  -   POST /auth/tfa/disable       {password} to remove TFA (will block /protected again)")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
