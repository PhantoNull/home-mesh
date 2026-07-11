//go:build windows

package sshclient

import "os"

// Windows ACL validation is deployment-specific. Lstat still rejects links
// and non-regular paths; the deployment runbook requires a restricted ACL.
func validateKnownHostsPermissions(os.FileInfo) error {
	return nil
}
