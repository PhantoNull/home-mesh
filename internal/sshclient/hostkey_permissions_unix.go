//go:build !windows

package sshclient

import (
	"fmt"
	"os"
	"syscall"
)

func validateKnownHostsPermissions(info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("known_hosts file must not be writable by group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect known_hosts file owner")
	}
	owner := int(stat.Uid)
	if owner != 0 && owner != os.Geteuid() {
		return fmt.Errorf("known_hosts file must be owned by the current user or root")
	}
	return nil
}
