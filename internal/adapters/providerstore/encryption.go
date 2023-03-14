package providerstore

import (
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

type gcmEncryptor struct {
	cipher encryption.Cipher
}

func (g gcmEncryptor) Encrypt(val string) (string, error) {
	res, err := g.cipher.Encrypt([]byte(val))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func (g gcmEncryptor) Decrypt(val string) (string, error) {
	res, err := g.cipher.Decrypt([]byte(val))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func NewGCMEncryptor(secret string) (models.Encryptor, error) {
	cipher, err := encryption.NewGCMCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	return gcmEncryptor{cipher: cipher}, nil
}
