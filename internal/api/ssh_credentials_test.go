package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestValidateSSHCredentialsRotatesLegacyRows(t *testing.T) {
	encodedKey := randomEncodedKey(t)
	legacy, err := secrets.New(encodedKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := legacy.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	inventory := &fakeSSHCredentialInventory{credentials: []store.SSHCredential{{
		DeviceID:           "device-a",
		Username:           "root",
		PasswordCiphertext: ciphertext,
		PasswordNonce:      nonce,
		HasPassword:        true,
		KeyVersion:         1,
	}}}
	keyring, err := secrets.NewKeyring(encodedKey, 2, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateSSHCredentials(context.Background(), inventory, keyring); err != nil {
		t.Fatalf("validate credentials: %v", err)
	}
	if inventory.upserts != 1 || inventory.credentials[0].KeyVersion != 2 {
		t.Fatalf("credential was not rotated: %+v", inventory.credentials)
	}
	plaintext, err := keyring.DecryptFor("ssh-credential:device-a", inventory.credentials[0].PasswordCiphertext, inventory.credentials[0].PasswordNonce, 2)
	if err != nil || plaintext != "secret" {
		t.Fatalf("rotated credential = %q, %v", plaintext, err)
	}
}

func TestValidateSSHCredentialsRejectsMissingOrWrongKey(t *testing.T) {
	encodedKey := randomEncodedKey(t)
	legacy, err := secrets.New(encodedKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := legacy.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	credential := store.SSHCredential{
		DeviceID:           "device-a",
		PasswordCiphertext: ciphertext,
		PasswordNonce:      nonce,
		HasPassword:        true,
		KeyVersion:         1,
	}

	for _, test := range []struct {
		name    string
		service *secrets.Service
	}{
		{name: "missing"},
		{name: "wrong", service: mustKeyring(t, randomEncodedKey(t), 2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventory := &fakeSSHCredentialInventory{credentials: []store.SSHCredential{credential}}
			err := ValidateSSHCredentials(context.Background(), inventory, test.service)
			if err == nil || !strings.Contains(err.Error(), "device-a") && test.name == "wrong" {
				t.Fatalf("error = %v", err)
			}
			if inventory.upserts != 0 {
				t.Fatal("unreadable credential was modified")
			}
		})
	}
}

func TestValidateSSHCredentialsDoesNotRequireKeyForEmptyStore(t *testing.T) {
	inventory := &fakeSSHCredentialInventory{}
	if err := ValidateSSHCredentials(context.Background(), inventory, nil); err != nil {
		t.Fatalf("empty credential store: %v", err)
	}
}

type fakeSSHCredentialInventory struct {
	credentials []store.SSHCredential
	listErr     error
	upsertErr   error
	upserts     int
}

func (f *fakeSSHCredentialInventory) ListSSHCredentials(context.Context) ([]store.SSHCredential, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]store.SSHCredential(nil), f.credentials...), nil
}

func (f *fakeSSHCredentialInventory) UpsertSSHCredential(_ context.Context, credential store.SSHCredential) (store.SSHCredential, error) {
	if f.upsertErr != nil {
		return store.SSHCredential{}, f.upsertErr
	}
	f.upserts++
	for index := range f.credentials {
		if f.credentials[index].DeviceID == credential.DeviceID {
			f.credentials[index] = credential
			return credential, nil
		}
	}
	return store.SSHCredential{}, errors.New("credential not found")
}

func randomEncodedKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func mustKeyring(t *testing.T, key string, version int) *secrets.Service {
	t.Helper()
	service, err := secrets.NewKeyring(key, version, nil)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
