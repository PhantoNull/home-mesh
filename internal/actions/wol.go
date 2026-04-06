package actions

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func SendWakeOnLAN(macAddress string) error {
	hardwareAddr, err := net.ParseMAC(macAddress)
	if err != nil {
		return fmt.Errorf("parse mac address: %w", err)
	}

	if len(hardwareAddr) != 6 {
		return errors.New("wake-on-lan requires a 6-byte MAC address")
	}

	payload := make([]byte, 0, 102)
	payload = append(payload, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
	for i := 0; i < 16; i++ {
		payload = append(payload, hardwareAddr...)
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: 9,
	})
	if err != nil {
		return fmt.Errorf("open udp broadcast socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetWriteBuffer(len(payload)); err != nil {
		return fmt.Errorf("set write buffer: %w", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("send magic packet to %s: %w", strings.ToUpper(macAddress), err)
	}

	return nil
}
