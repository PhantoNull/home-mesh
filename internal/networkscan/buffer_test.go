package networkscan

import (
	"bytes"
	"testing"
)

func TestBoundedBufferReportsFullWritesWhileRetainingOnlyTheLimit(t *testing.T) {
	buffer := NewBoundedBuffer(8)
	input := bytes.Repeat([]byte("x"), 64*1024)
	written, err := buffer.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", written, err, len(input))
	}
	if buffer.Len() != 8 || buffer.Total() != int64(len(input)) || !buffer.Truncated() {
		t.Fatalf("len=%d total=%d truncated=%t", buffer.Len(), buffer.Total(), buffer.Truncated())
	}
	if got := buffer.String(); got != "xxxxxxxx" {
		t.Fatalf("retained data = %q", got)
	}
}
