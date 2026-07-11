//go:build windows

package actions

import (
	"net"

	"golang.org/x/sys/windows"
)

func enableSocketBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(handle uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(handle), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return socketErr
}
