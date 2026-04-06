package secrets

import (
	"crypto/rand"
	"encoding/base64"
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
