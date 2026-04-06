package api

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("hashPassword returned empty hash")
	}
	if !verifyPassword("s3cret-pass", hash) {
		t.Fatal("verifyPassword rejected correct password")
	}
	if verifyPassword("wrong-pass", hash) {
		t.Fatal("verifyPassword accepted wrong password")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	if verifyPassword("irrelevant", "not-a-valid-hash") {
		t.Fatal("verifyPassword accepted malformed hash")
	}
}
