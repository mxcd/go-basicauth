# go-basicauth

Session-based authentication for Gin applications. Handles user registration, login, and session management with sensible defaults.

## Install

```bash
go get github.com/mxcd/go-basicauth
```

## Quick Start

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/mxcd/go-basicauth"
)

func main() {
    r := gin.Default()

    // Generate session keys (store these securely in production)
    secretKey, _ := basicauth.GenerateSessionSecretKey()
    encryptionKey, _ := basicauth.GenerateSessionEncryptionKey()

    settings := basicauth.DefaultSettings()
    settings.SessionSecretKey = secretKey
    settings.SessionEncryptionKey = encryptionKey

    // You need to provide your own storage implementation
    storage := &MyDatabaseStorage{}

    handler, _ := basicauth.NewHandler(&basicauth.Options{
        Engine:                r,
        AuthenticationBaseUrl: "/auth",
        Storage:               storage,
        Settings:              settings,
    })

    handler.RegisterRoutes()

    // Protected routes
    r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
        user, _ := basicauth.GetUserFromContext(c)
        c.JSON(200, gin.H{"user": user.Username})
    })

    r.Run(":8080")
}
```

## Routes

The library sets up these endpoints under your configured base URL (default `/auth`):

- `POST /auth/register` - Create new user
- `POST /auth/login` - Login with username or email
- `POST /auth/logout` - Clear session
- `GET /auth/me` - Get current user info

When `Settings.EnableTFA` is true, the following are also registered:

- `POST /auth/tfa/setup` - Begin TOTP enrollment, returns secret + otpauth URI
- `POST /auth/tfa/enable` - Confirm enrollment with a TOTP code, returns backup codes
- `POST /auth/tfa/disable` - Disable TFA (requires password)
- `POST /auth/tfa/verify` - Complete login by submitting TOTP or backup code

## Storage

You need to implement the `Storage` interface for your database:

```go
type Storage interface {
    CreateUser(user *User) error
    GetUserByUsername(username string) (*User, error)
    GetUserByEmail(email string) (*User, error)
    GetUserByID(id uuid.UUID) (*User, error)
    UpdateUser(user *User) error
    DeleteUser(id uuid.UUID) error
}
```

An in-memory implementation is provided for testing:

```go
storage := basicauth.NewMemoryStorage()
```

## Configuration

```go
settings := basicauth.DefaultSettings()

// Login methods
settings.EnableUsernameLogin = true
settings.EnableEmailLogin = true

// Session
settings.SessionExpiration = 24 * time.Hour
settings.SessionName = "my_session"

// Password requirements
settings.PasswordRequirements.MinLength = 10
settings.PasswordRequirements.RequireUppercase = true
settings.PasswordRequirements.RequireLowercase = true
settings.PasswordRequirements.RequireNumbers = true
settings.PasswordRequirements.RequireSpecial = false

// Cookie settings
settings.CookieSecure = true  // Set to false for local dev without HTTPS
settings.CookieHttpOnly = true
settings.CookieSameSite = http.SameSiteLaxMode

// Custom messages
settings.Messages.LoginSuccess = "Welcome back"
settings.Messages.InvalidCredentials = "Wrong credentials"
```

## Path-Based Access Control

Configure paths that don't require authentication (public) or explicitly require it (private). Longer paths take precedence, so you can set `/` as public and override specific paths like `/api` as private.

```go
settings.PathRules = []basicauth.PathRule{
    // Make all UI routes public
    {Type: basicauth.PublicPathPrefix, Path: "/", Access: basicauth.PathAccessPublic},

    // But require auth for /api routes
    {Type: basicauth.PublicPathPrefix, Path: "/api", Access: basicauth.PathAccessPrivate},

    // Except for health checks
    {Type: basicauth.PublicPathExact, Path: "/api/v1/health", Access: basicauth.PathAccessPublic},
}
```

**How it works:**
- The middleware finds all matching rules for a request path
- It selects the longest matching path (most specific wins)
- It applies the access control from that rule
- If no rule matches, authentication is required by default

**Example:**
- Request to `/` → matches `/` prefix (public) → allowed
- Request to `/about` → matches `/` prefix (public) → allowed
- Request to `/api/users` → matches both `/` and `/api` prefixes, `/api` is longer (private) → requires auth
- Request to `/api/v1/health` → matches `/`, `/api`, and exact `/api/v1/health`, exact match is longest (public) → allowed

**Backward compatibility:**
The old `PublicPaths` field still works and is treated as public rules. Use `PathRules` for the new precedence-based system.

## Two-Factor Authentication (TOTP)

Opt-in second factor for authenticator apps (Google Authenticator, 1Password, Authy, ...) using TOTP (RFC 6238). Each user enrolls themselves; backup codes are issued once at enrollment for account recovery.

### Enabling

```go
settings := basicauth.DefaultSettings()
settings.EnableTFA = true
settings.TFA.Issuer = "MyApp" // required — shown in the authenticator app

// Optional tuning (defaults shown)
settings.TFA.Period = 30                         // seconds per code
settings.TFA.Digits = 6                          // digits per code
settings.TFA.SkewWindows = 1                     // ±1 period tolerance
settings.TFA.BackupCodeCount = 10                // 0 disables backup codes
settings.TFA.BackupCodeLength = 10               // characters per code
settings.TFA.BackupCodeAlphabet = "0123456789"   // e.g. "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" for Crockford-style
settings.TFA.MaxVerifyAttempts = 5               // wrong codes tolerated before pending session dies (0 = unlimited)
settings.TFA.Required = false                    // when true, all authenticated users must enroll before accessing protected routes
settings.TFA.PendingSessionTTL = 5 * time.Minute // how long the "password ok, code pending" cookie lives

// Optional: override the otpauth account label (defaults to username, then email)
settings.TFA.AccountLabel = func(u *basicauth.User) string {
    if u.Email != nil {
        return *u.Email
    }
    return u.ID.String()
}
```

When `EnableTFA` is false (the default), the `/auth/tfa/*` routes are not registered and login works exactly as before. Existing users keep working — TFA is per-user opt-in.

### Enrollment flow

1. User is logged in normally (password-only at this point).
2. `POST /auth/tfa/setup` — returns `{ secret, otpauthUrl, issuer, accountName }`. Render `otpauthUrl` as a QR code, or show `secret` for manual entry. The secret is stashed server-side in the session until the user confirms it.
3. User scans the QR / enters the secret into their authenticator app, reads back the 6-digit code.
4. `POST /auth/tfa/enable` with `{ "code": "123456" }` — verifies the code against the pending secret, persists TFA on the user, and returns `{ backupCodes: [...] }`. **Show these to the user exactly once.** They are not recoverable.

### Login flow (once enrolled)

1. `POST /auth/login` with `{ identifier, password }`. Instead of `200`, the server responds **`202 Accepted`** with `{ "data": { "tfaRequired": true } }` and sets a short-lived pending cookie (no full session yet).
2. `POST /auth/tfa/verify` with `{ "code": "123456" }` — promotes the pending cookie to a full session. From here everything behaves like the normal post-login state.
3. If the user lost their authenticator, they can submit a backup code instead: `{ "code": "abcdef0123", "isBackupCode": true }`. Each code works once.

If TFA is **not** enrolled for the user, the `/auth/login` response is the usual `200` and no follow-up call is needed.

### Disabling

```
POST /auth/tfa/disable
{ "password": "CurrentPassword123" }
```

Password is required to prevent a cookie-only attacker from turning 2FA off. On success, the secret and all backup codes are cleared. To rotate codes, disable and re-enable.

### Example requests

Enroll:

```bash
# (cookies.txt already holds a logged-in session)
curl -X POST http://localhost:8080/auth/tfa/setup -b cookies.txt -c cookies.txt
# → { "secret": "JBSWY3DPEHPK3PXP", "otpauthUrl": "otpauth://totp/MyApp:alice?...", ... }

curl -X POST http://localhost:8080/auth/tfa/enable \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}' \
  -b cookies.txt -c cookies.txt
# → { "backupCodes": ["abcdef0123", "..."] }
```

Login with 2FA:

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"SecurePass123"}' \
  -c cookies.txt
# → 202 { "message": "Two-factor authentication required", "data": { "tfaRequired": true } }

curl -X POST http://localhost:8080/auth/tfa/verify \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}' \
  -b cookies.txt -c cookies.txt
# → 200, full session cookie
```

Disable 2FA (requires current password, session cookie):

```bash
curl -X POST http://localhost:8080/auth/tfa/disable \
  -H "Content-Type: application/json" \
  -d '{"password":"SecurePass123"}' \
  -b cookies.txt
# → 200 { "message": "Two-factor authentication disabled" }
```

### Enforced mode

Set `TFA.Required = true` to make two-factor mandatory for every user. After login, any authenticated user without TOTP enabled gets a `403 Forbidden` with `{ "error": "tfa_setup_required" }` on protected routes. The following endpoints stay reachable so the user can finish enrolling:

- `GET  /auth/me`          — check current state (`totpEnabled` on the user response)
- `POST /auth/logout`
- `POST /auth/tfa/setup`
- `POST /auth/tfa/enable`

Typical client behavior: on any `403 tfa_setup_required`, redirect the user to your TFA setup screen.

Required mode only takes effect when `EnableTFA` is also `true`.

### Race-free backup code consumption (optional)

Backup codes are one-shot. The default flow — read user, verify code, rewrite user via `Storage.UpdateUser` — has a narrow race: two concurrent requests submitting the same code can both succeed before either write lands. If that matters to you, implement the optional `AtomicBackupCodeConsumer` interface on your `Storage`:

```go
type AtomicBackupCodeConsumer interface {
    ConsumeBackupCodeHash(userID uuid.UUID, hash string) (removed bool, err error)
}
```

For SQL backends this is typically a conditional `UPDATE` such as
`UPDATE users SET backup_codes = array_remove(backup_codes, $hash) WHERE id = $id AND $hash = ANY(backup_codes)`,
using the affected-row count to return `removed`. If your `Storage` implements this interface, the library uses it automatically; otherwise it falls back to the standard `UpdateUser` path. The provided `MemoryStorage` already implements it under its mutex.

### Rate limiting

`/auth/login` has no built-in rate limiting — neither does any other route. Put throttling at your reverse proxy or as Gin middleware. `/auth/tfa/verify` does have one built-in guard: the `MaxVerifyAttempts` counter lives in the pending session, and when it's exhausted the pending session is invalidated (user has to log in again). That prevents unlimited guessing against a single captured pending cookie but does **not** prevent an attacker from repeatedly re-logging-in to get fresh pending sessions. External rate limiting is still your responsibility.

A runnable end-to-end example lives in `examples/tfa/main.go` (`just example-tfa`).

## User Context

Store authenticated users in Go's standard `context.Context` for easy access in handlers. This uses the idiomatic Go context pattern.

### Basic Usage

Define a context key and configure the handler:

```go
// Define a context key (use a custom type to avoid collisions)
type userContextKey struct{}
var UserKey = userContextKey{}

// Configure the handler
handler, _ := basicauth.NewHandler(&basicauth.Options{
    Engine:   r,
    Storage:  storage,
    Settings: settings,
    UserKey:  UserKey,  // User will be stored under this key
})
```

Access the user in handlers:

```go
r.GET("/profile", handler.RequireAuth(), func(c *gin.Context) {
    user := c.Request.Context().Value(UserKey).(*basicauth.User)
    c.JSON(200, gin.H{"username": user.Username})
})
```

### Custom User Transformation

Use `UserTransformer` to convert `basicauth.User` to your application's user type before storing:

```go
handler, _ := basicauth.NewHandler(&basicauth.Options{
    Engine:   r,
    Storage:  storage,
    Settings: settings,
    UserKey:  UserKey,
    UserTransformer: func(c *gin.Context, user *basicauth.User) any {
        // Fetch full user from your database
        dbUser, _ := db.GetUserByID(user.ID)
        return dbUser  // Store your custom type instead
    },
})
```

### Type-Safe Access Helper

Create a helper function for type-safe user access:

```go
func GetUser(ctx context.Context) *MyUser {
    if user, ok := ctx.Value(UserKey).(*MyUser); ok {
        return user
    }
    return nil
}

// Usage in handlers
func profileHandler(c *gin.Context) {
    user := GetUser(c.Request.Context())
    // ...
}
```

**When context is set:**
- After successful login
- After successful registration
- In the `RequireAuth` middleware after session validation

If `UserKey` is nil, no user is stored in context (backward compatible).

## Security

Sessions are signed with a 64-byte key and encrypted with a 32-byte key using gorilla/sessions. Generate these keys with:

```go
secretKey, _ := basicauth.GenerateSessionSecretKey()       // 64 bytes
encryptionKey, _ := basicauth.GenerateSessionEncryptionKey() // 32 bytes
```

Store these keys securely. Don't commit them to your repository. Use environment variables or a secrets manager.

Passwords are hashed with Argon2id. The library prevents user enumeration by returning generic error messages for failed logins.

TOTP secrets are stored verbatim on the `User` (base32, as produced by the authenticator standard). Your `Storage` implementation is responsible for encryption at rest if required. Backup codes are never stored in the clear — they are hashed with Argon2id the same way passwords are.

## Example Requests

Register:
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"SecurePass123"}'
```

Login:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"SecurePass123"}' \
  -c cookies.txt
```

Access protected route:
```bash
curl http://localhost:8080/protected -b cookies.txt
```

## Testing

```bash
go test ./...
```

Check out `examples/simple/main.go` for a working example with in-memory storage, or `examples/tfa/main.go` for the same example with two-factor authentication enabled.

## License

MIT
