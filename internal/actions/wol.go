package actions

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	defaultWakeAddress = "255.255.255.255:9"
	defaultWakeTimeout = 3 * time.Second
)

func SendWakeOnLAN(macAddress string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultWakeTimeout)
	defer cancel()
	return SendWakeOnLANContext(ctx, macAddress)
}

func SendWakeOnLANContext(ctx context.Context, macAddress string) error {
	return sendWakeOnLANTo(ctx, macAddress, defaultWakeAddress)
}

func sendWakeOnLANTo(ctx context.Context, macAddress string, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := magicPacket(macAddress)
	if err != nil {
		return err
	}
	address, err := net.ResolveUDPAddr("udp4", destination)
	if err != nil {
		return fmt.Errorf("resolve wake-on-lan destination: %w", err)
	}
	if address.IP == nil || address.IP.To4() == nil || address.Port < 1 || address.Port > 65535 {
		return errors.New("wake-on-lan destination must be an IPv4 address with a valid port")
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("open udp broadcast socket: %w", err)
	}
	defer conn.Close()
	if err := enableSocketBroadcast(conn); err != nil {
		return fmt.Errorf("enable udp broadcast: %w", err)
	}

	deadline := time.Now().Add(defaultWakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set wake-on-lan deadline: %w", err)
	}
	stopCloseOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCloseOnCancel()

	if _, err := conn.WriteToUDP(payload, address); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("send magic packet to %s: %w", strings.ToUpper(macAddress), err)
	}
	return nil
}

func magicPacket(macAddress string) ([]byte, error) {
	hardwareAddr, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, fmt.Errorf("parse mac address: %w", err)
	}

	if len(hardwareAddr) != 6 {
		return nil, errors.New("wake-on-lan requires a 6-byte MAC address")
	}
	allZero := true
	for _, value := range hardwareAddr {
		allZero = allZero && value == 0
	}
	if hardwareAddr[0]&1 != 0 || allZero {
		return nil, errors.New("wake-on-lan requires a non-zero unicast MAC address")
	}

	payload := make([]byte, 0, 102)
	payload = append(payload, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
	for i := 0; i < 16; i++ {
		payload = append(payload, hardwareAddr...)
	}
	return payload, nil
}
