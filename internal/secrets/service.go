package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrUnavailable = errors.New("secrets service unavailable")

var ErrUnknownKeyVersion = errors.New("unknown secret key version")

type Service struct {
	currentVersion int
	keys           map[int][]byte
}

func New(encodedKey string) (*Service, error) {
	return NewKeyring(encodedKey, 1, nil)
}

func NewKeyring(encodedKey string, currentVersion int, previousKeys map[int]string) (*Service, error) {
	if encodedKey == "" {
		return nil, ErrUnavailable
	}
	if currentVersion <= 0 {
		return nil, errors.New("master key version must be positive")
	}

	key, err := decodeKey(encodedKey)
	if err != nil {
		return nil, err
	}

	keys := map[int][]byte{currentVersion: key}
	// Version 2 is the first scoped format. Reuse the existing key for legacy
	// version-1 rows during the initial in-place upgrade.
	if currentVersion == 2 {
		keys[1] = key
	}
	for version, encodedPreviousKey := range previousKeys {
		if version <= 0 {
			return nil, fmt.Errorf("previous master key version %d must be positive", version)
		}
		if version >= currentVersion {
			return nil, fmt.Errorf("previous master key version %d must be lower than current version %d", version, currentVersion)
		}
		previousKey, err := decodeKey(encodedPreviousKey)
		if err != nil {
			return nil, fmt.Errorf("decode previous master key version %d: %w", version, err)
		}
		keys[version] = previousKey
	}

	return &Service{currentVersion: currentVersion, keys: keys}, nil
}

func (s *Service) Encrypt(plaintext string) (ciphertext string, nonce string, err error) {
	ciphertext, nonce, _, err = s.EncryptFor("", plaintext)
	return ciphertext, nonce, err
}

func (s *Service) EncryptFor(scope string, plaintext string) (ciphertext string, nonce string, keyVersion int, err error) {
	if s == nil {
		return "", "", 0, ErrUnavailable
	}
	key, ok := s.keys[s.currentVersion]
	if !ok {
		return "", "", 0, fmt.Errorf("%w: %d", ErrUnknownKeyVersion, s.currentVersion)
	}
	associatedData, err := associatedDataFor(s.currentVersion, scope)
	if err != nil {
		return "", "", 0, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", "", 0, fmt.Errorf("create xchacha20-poly1305: %w", err)
	}

	nonceBytes := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", 0, fmt.Errorf("generate nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonceBytes, []byte(plaintext), associatedData)
	return base64.StdEncoding.EncodeToString(sealed), base64.StdEncoding.EncodeToString(nonceBytes), s.currentVersion, nil
}

func (s *Service) Decrypt(ciphertext string, nonce string) (string, error) {
	if s == nil {
		return "", ErrUnavailable
	}
	return s.DecryptFor("", ciphertext, nonce, s.currentVersion)
}

func (s *Service) DecryptFor(scope string, ciphertext string, nonce string, keyVersion int) (string, error) {
	if s == nil {
		return "", ErrUnavailable
	}
	key, ok := s.keys[keyVersion]
	if !ok {
		return "", fmt.Errorf("%w: %d", ErrUnknownKeyVersion, keyVersion)
	}
	associatedData, err := associatedDataFor(keyVersion, scope)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(key)
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
	if len(nonceBytes) != chacha20poly1305.NonceSizeX {
		return "", fmt.Errorf("nonce must decode to %d bytes", chacha20poly1305.NonceSizeX)
	}

	plaintext, err := aead.Open(nil, nonceBytes, ciphertextBytes, associatedData)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}

	return string(plaintext), nil
}

func (s *Service) CurrentVersion() int {
	if s == nil {
		return 0
	}
	return s.currentVersion
}

func decodeKey(encodedKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("master key must decode to %d bytes", chacha20poly1305.KeySize)
	}
	return key, nil
}

func associatedDataFor(keyVersion int, scope string) ([]byte, error) {
	if keyVersion <= 1 {
		return nil, nil
	}
	if scope == "" {
		return nil, errors.New("secret scope is required for key version 2 or newer")
	}
	return []byte(scope), nil
}
