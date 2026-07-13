package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/store"
)

type sshCredentialInventory interface {
	ListSSHCredentials(context.Context) ([]store.SSHCredential, error)
	UpsertSSHCredential(context.Context, store.SSHCredential) (store.SSHCredential, error)
}

func sshCredentialScope(deviceID string) string {
	return "ssh-credential:" + deviceID
}

func currentSecretVersion(service *secrets.Service) int {
	if service == nil {
		return 0
	}
	return service.CurrentVersion()
}

func decryptAndRotateSSHCredential(ctx context.Context, inventory sshCredentialInventory, service *secrets.Service, credential store.SSHCredential) (string, error) {
	if service == nil {
		return "", secrets.ErrUnavailable
	}
	if !credential.HasPassword || credential.PasswordCiphertext == "" || credential.PasswordNonce == "" {
		return "", errors.New("SSH credential has no encrypted password")
	}

	password, err := service.DecryptFor(
		sshCredentialScope(credential.DeviceID),
		credential.PasswordCiphertext,
		credential.PasswordNonce,
		credential.KeyVersion,
	)
	if err != nil {
		return "", err
	}
	if credential.KeyVersion == service.CurrentVersion() {
		return password, nil
	}

	ciphertext, nonce, keyVersion, err := service.EncryptFor(sshCredentialScope(credential.DeviceID), password)
	if err != nil {
		return "", fmt.Errorf("rotate SSH credential encryption: %w", err)
	}
	credential.PasswordCiphertext = ciphertext
	credential.PasswordNonce = nonce
	credential.KeyVersion = keyVersion
	if _, err := inventory.UpsertSSHCredential(ctx, credential); err != nil {
		return "", fmt.Errorf("persist rotated SSH credential: %w", err)
	}
	return password, nil
}

// ValidateSSHCredentials proves that every persisted credential is readable by
// the configured keyring and upgrades legacy key versions before serving traffic.
func ValidateSSHCredentials(ctx context.Context, inventory sshCredentialInventory, service *secrets.Service) error {
	credentials, err := inventory.ListSSHCredentials(ctx)
	if err != nil {
		return fmt.Errorf("list SSH credentials for key validation: %w", err)
	}
	if len(credentials) == 0 {
		return nil
	}
	if service == nil {
		return errors.New("persisted SSH credentials require HOME_MESH_MASTER_KEY")
	}

	for _, credential := range credentials {
		if _, err := decryptAndRotateSSHCredential(ctx, inventory, service, credential); err != nil {
			return fmt.Errorf("validate SSH credential for device %q: %w", credential.DeviceID, err)
		}
	}
	return nil
}
