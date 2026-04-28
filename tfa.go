package basicauth

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func tfaAccountLabel(settings *TFASettings, user *User) string {
	if settings.AccountLabel != nil {
		if label := settings.AccountLabel(user); label != "" {
			return label
		}
	}
	if user.Username != nil && *user.Username != "" {
		return *user.Username
	}
	if user.Email != nil && *user.Email != "" {
		return *user.Email
	}
	return user.ID.String()
}

func generateTOTPKey(settings *TFASettings, user *User) (*otp.Key, error) {
	if settings.Issuer == "" {
		return nil, errors.New("TFA.Issuer is required")
	}
	return totp.Generate(totp.GenerateOpts{
		Issuer:      settings.Issuer,
		AccountName: tfaAccountLabel(settings, user),
		Period:      settings.Period,
		Digits:      otp.Digits(settings.Digits),
	})
}

func validateTOTPCode(secret, code string, settings *TFASettings) bool {
	ok, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now(), totp.ValidateOpts{
		Period: settings.Period,
		Skew:   settings.SkewWindows,
		Digits: otp.Digits(settings.Digits),
	})
	if err != nil {
		return false
	}
	return ok
}

func generateBackupCodes(count, length int, alphabet string, params Params) (plain, hashed []string, err error) {
	if length <= 0 {
		return nil, nil, errors.New("TFA.BackupCodeLength must be > 0")
	}
	// Normalize to lowercase so issued codes and their hashes agree with the
	// case-insensitive verification path in findBackupCodeMatch.
	alphabet = strings.ToLower(alphabet)
	seen := make(map[rune]struct{}, len(alphabet))
	for _, r := range alphabet {
		seen[r] = struct{}{}
	}
	if len(seen) < 2 {
		return nil, nil, errors.New("TFA.BackupCodeAlphabet must contain at least 2 distinct characters")
	}

	plain = make([]string, count)
	hashed = make([]string, count)
	alpha := []rune(alphabet)
	max := big.NewInt(int64(len(alpha)))

	for i := range count {
		code := make([]rune, length)
		for j := range length {
			n, rErr := rand.Int(rand.Reader, max)
			if rErr != nil {
				return nil, nil, rErr
			}
			code[j] = alpha[n.Int64()]
		}
		plainCode := string(code)
		h, hErr := HashPassword(plainCode, params)
		if hErr != nil {
			return nil, nil, hErr
		}
		plain[i] = plainCode
		hashed[i] = h
	}
	return plain, hashed, nil
}

// findBackupCodeMatch returns the first hash that verifies the given code.
// It does not mutate the slice — removal is the caller's responsibility so
// an atomic Storage implementation can do it race-free.
func findBackupCodeMatch(hashes []string, code string) (string, bool) {
	code = strings.ToLower(strings.TrimSpace(code))
	for _, h := range hashes {
		valid, _, err := VerifyPassword(code, h)
		if err == nil && valid {
			return h, true
		}
	}
	return "", false
}

func removeHash(hashes []string, hash string) []string {
	for i, h := range hashes {
		if h == hash {
			return append(hashes[:i:i], hashes[i+1:]...)
		}
	}
	return hashes
}
