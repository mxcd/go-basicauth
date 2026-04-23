package basicauth

import "crypto/rand"

func GenerateSessionSecretKey() ([]byte, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateSessionEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Deprecated: Use GenerateSessionSecretKey or GenerateSessionEncryptionKey
func GenerateSessionKey() ([]byte, error) {
	return GenerateSessionSecretKey()
}

func ToUserResponse(user *User) UserResponse {
	return UserResponse{
		ID:              user.ID,
		Username:        user.Username,
		Email:           user.Email,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
		IsTechnicalUser: user.IsTechnicalUser,
		TOTPEnabled:     user.TOTPEnabled,
	}
}
