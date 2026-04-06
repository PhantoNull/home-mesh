package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrUnavailable = errors.New("secrets service unavailable")

type Service struct {
	key []byte
}

func New(encodedKey string) (*Service, error) {
	if encodedKey == "" {
		return nil, ErrUnavailable
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("master key must decode to %d bytes", chacha20poly1305.KeySize)
	}

	return &Service{key: key}, nil
}

func (s *Service) Encrypt(plaintext string) (ciphertext string, nonce string, err error) {
	if s == nil {
		return "", "", ErrUnavailable
	}

	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return "", "", fmt.Errorf("create xchacha20-poly1305: %w", err)
	}

	nonceBytes := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonceBytes, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), base64.StdEncoding.EncodeToString(nonceBytes), nil
}

func (s *Service) Decrypt(ciphertext string, nonce string) (string, error) {
	if s == nil {
		return "", ErrUnavailable
	}

	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return "", fmt.Errorf("create xchacha20-poly1305: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}

	plaintext, err := aead.Open(nil, nonceBytes, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}

	return string(plaintext), nil
}
