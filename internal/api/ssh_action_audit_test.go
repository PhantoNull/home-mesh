package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestSSHCommandAuditDataExcludesCommandAndOutputPlaintext(t *testing.T) {
	t.Parallel()

	command := "cat /private/command-sentinel"
	output := "output-sentinel: super secret value"
	metadata := sshCommandCompletionMetadata(sshclient.Result{
		Output:    output,
		Truncated: true,
	}, nil)
	action := store.Action{
		ActionType:    "ssh_command",
		ResultSummary: "SSH command completed.",
		Metadata:      metadata,
	}

	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal action: %v", err)
	}
	serialized := string(encoded)
	for _, plaintext := range []string{command, output} {
		if strings.Contains(serialized, plaintext) {
			t.Fatalf("audit contains plaintext %q: %s", plaintext, serialized)
		}
	}
	if _, exists := metadata["command"]; exists {
		t.Fatalf("audit metadata contains command field: %v", metadata)
	}
	if _, exists := metadata["output"]; exists {
		t.Fatalf("audit metadata contains output field: %v", metadata)
	}
	if _, exists := metadata["commandHash"]; exists {
		t.Fatalf("audit metadata contains command digest: %v", metadata)
	}
	if strings.Contains(serialized, "sha256:") {
		t.Fatalf("audit contains a command digest: %s", serialized)
	}
	if metadata["capturedOutputBytes"] != "35" || metadata["outputTruncated"] != "true" {
		t.Fatalf("completion metadata = %v", metadata)
	}
}

func TestSSHCommandTerminationReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "completed", want: "completed"},
		{name: "cancelled", err: contextCanceledError(), want: "context_cancelled"},
		{name: "timeout", err: contextDeadlineError(), want: "timeout"},
		{name: "execution error", err: errors.New("exit status 1"), want: "execution_error"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := sshCommandTerminationReason(test.err); got != test.want {
				t.Fatalf("termination reason = %q, want %q", got, test.want)
			}
		})
	}
}

func contextCanceledError() error {
	return fmt.Errorf("wrapped: %w", context.Canceled)
}

func contextDeadlineError() error {
	return fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
}
