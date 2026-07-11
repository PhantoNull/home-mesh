package actions

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestMagicPacketLayout(t *testing.T) {
	packet, err := magicPacket("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("magic packet: %v", err)
	}
	if len(packet) != 102 {
		t.Fatalf("packet length = %d, want 102", len(packet))
	}
	if !bytes.Equal(packet[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("packet prefix = %x", packet[:6])
	}
	wantMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for offset := 6; offset < len(packet); offset += len(wantMAC) {
		if !bytes.Equal(packet[offset:offset+len(wantMAC)], wantMAC) {
			t.Fatalf("MAC repetition at %d = %x", offset, packet[offset:offset+len(wantMAC)])
		}
	}
}

func TestMagicPacketRejectsUnsafeEthernetAddress(t *testing.T) {
	for _, address := range []string{
		"invalid",
		"01:02:03:04:05:06:07:08",
		"00:00:00:00:00:00",
		"FF:FF:FF:FF:FF:FF",
		"01:00:5E:00:00:01",
	} {
		if _, err := magicPacket(address); err == nil {
			t.Fatalf("expected %q to be rejected", address)
		}
	}
}

func TestSendWakeOnLANHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SendWakeOnLANContext(ctx, "AA:BB:CC:DD:EE:FF"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestSendWakeOnLANWritesPacketToDestination(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendWakeOnLANTo(ctx, "AA:BB:CC:DD:EE:FF", listener.LocalAddr().String()); err != nil {
		t.Fatalf("send wake packet: %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	count, _, err := listener.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read wake packet: %v", err)
	}
	want, _ := magicPacket("AA:BB:CC:DD:EE:FF")
	if !bytes.Equal(buffer[:count], want) {
		t.Fatalf("received packet = %x", buffer[:count])
	}
}
