package basicauth

import "golang.org/x/crypto/bcrypt"

// BcryptVerifier is a ready-made LegacyPasswordVerifier for bcrypt hashes —
// the format used by PocketBase, Django, Rails, and many others. Wire it in to
// let users with imported bcrypt credentials log in:
//
//	settings.LegacyPasswordVerifier = basicauth.BcryptVerifier
//
// On each user's next successful login the library transparently re-hashes
// their password with argon2id (see Settings.LegacyPasswordVerifier), so the
// bcrypt hashes fade out one login at a time without a bulk password reset.
//
// bcrypt compares only the first 72 bytes of the password (it truncates, it
// does not error). A user whose imported password exceeds 72 bytes therefore
// still authenticates here, but cannot be re-hashed to argon2id — argon2 keys
// the full input, so a truncated re-hash would reject their next login. Such a
// user simply stays on bcrypt; see upgradePasswordHash. This matches the
// library's own 1–72 byte password limit (see HashPassword), so it only ever
// affects credentials imported from a system that allowed longer passwords.
func BcryptVerifier(password, storedHash string) (bool, error) {
	switch err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err {
	case nil:
		return true, nil
	case bcrypt.ErrMismatchedHashAndPassword:
		return false, nil
	default:
		// Malformed hash, unsupported version/cost, hash too short, etc. Surface
		// it rather than masquerading as a plain mismatch, so a bad import shows.
		// (Note: bcrypt does not report over-long passwords here — it truncates.)
		return false, err
	}
}
