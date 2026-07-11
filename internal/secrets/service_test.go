package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestServiceEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	service, err := New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	ciphertext, nonce, err := service.Encrypt("super-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ciphertext == "" || nonce == "" {
		t.Fatal("expected ciphertext and nonce to be populated")
	}

	plaintext, err := service.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != "super-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestServiceDecryptRejectsInvalidNonceLength(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	service, err := New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	ciphertext := base64.StdEncoding.EncodeToString(make([]byte, 32))
	shortNonce := base64.StdEncoding.EncodeToString(make([]byte, 1))

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Decrypt panicked for malformed nonce: %v", recovered)
		}
	}()

	_, err = service.Decrypt(ciphertext, shortNonce)
	if err == nil {
		t.Fatal("expected malformed nonce to be rejected")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce error, got %v", err)
	}
}

func TestVersionedEncryptionBindsCiphertextToScope(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	service, err := NewKeyring(base64.StdEncoding.EncodeToString(key), 2, nil)
	if err != nil {
		t.Fatalf("create keyring: %v", err)
	}

	ciphertext, nonce, version, err := service.EncryptFor("ssh-credential:device-a", "super-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if version != 2 {
		t.Fatalf("version %d want 2", version)
	}

	plaintext, err := service.DecryptFor("ssh-credential:device-a", ciphertext, nonce, version)
	if err != nil || plaintext != "super-secret" {
		t.Fatalf("decrypt matching scope = %q, %v", plaintext, err)
	}
	if _, err := service.DecryptFor("ssh-credential:device-b", ciphertext, nonce, version); err == nil {
		t.Fatal("expected a mismatched scope to fail authentication")
	}
}

func TestKeyringDecryptsPreviousVersion(t *testing.T) {
	t.Parallel()

	oldKey := make([]byte, 32)
	oldService, err := New(base64.StdEncoding.EncodeToString(oldKey))
	if err != nil {
		t.Fatalf("create legacy service: %v", err)
	}
	ciphertext, nonce, err := oldService.Encrypt("legacy-secret")
	if err != nil {
		t.Fatalf("encrypt legacy secret: %v", err)
	}

	newKey := make([]byte, 32)
	keyring, err := NewKeyring(base64.StdEncoding.EncodeToString(newKey), 2, map[int]string{
		1: base64.StdEncoding.EncodeToString(oldKey),
	})
	if err != nil {
		t.Fatalf("create rotated keyring: %v", err)
	}

	plaintext, err := keyring.DecryptFor("ssh-credential:device-a", ciphertext, nonce, 1)
	if err != nil || plaintext != "legacy-secret" {
		t.Fatalf("decrypt previous version = %q, %v", plaintext, err)
	}
}

func TestKeyringRejectsUnknownVersion(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	service, err := NewKeyring(base64.StdEncoding.EncodeToString(key), 2, nil)
	if err != nil {
		t.Fatalf("create keyring: %v", err)
	}

	_, err = service.DecryptFor("scope", "", "", 99)
	if !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("error %v want ErrUnknownKeyVersion", err)
	}
}

func TestKeyringRejectsNonPreviousKeyVersions(t *testing.T) {
	t.Parallel()

	encodedKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, version := range []int{2, 3} {
		if _, err := NewKeyring(encodedKey, 2, map[int]string{version: encodedKey}); err == nil {
			t.Fatalf("expected previous key version %d to be rejected", version)
		}
	}
}

func TestVersionTwoKeyringReadsLegacyRowsWithCurrentKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(key)
	legacy, err := New(encodedKey)
	if err != nil {
		t.Fatalf("create legacy service: %v", err)
	}
	ciphertext, nonce, err := legacy.Encrypt("legacy-secret")
	if err != nil {
		t.Fatalf("encrypt legacy secret: %v", err)
	}

	upgraded, err := NewKeyring(encodedKey, 2, nil)
	if err != nil {
		t.Fatalf("create upgraded keyring: %v", err)
	}
	plaintext, err := upgraded.DecryptFor("ssh-credential:device-a", ciphertext, nonce, 1)
	if err != nil || plaintext != "legacy-secret" {
		t.Fatalf("decrypt legacy row = %q, %v", plaintext, err)
	}
}
