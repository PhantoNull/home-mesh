package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/PhantoNull/home-mesh/internal/sshclient"
)

func sshCommandAuditHash(command string) string {
	digest := sha256.Sum256([]byte(command))
	return fmt.Sprintf("sha256:%x", digest)
}

func sshCommandCompletionMetadata(result sshclient.Result, err error) map[string]string {
	return map[string]string{
		"capturedOutputBytes": fmt.Sprintf("%d", len([]byte(result.Output))),
		"outputTruncated":     fmt.Sprintf("%t", result.Truncated),
		"terminationReason":   sshCommandTerminationReason(err),
	}
}

func sshCommandTerminationReason(err error) string {
	switch {
	case err == nil:
		return "completed"
	case errors.Is(err, context.Canceled):
		return "context_cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "execution_error"
	}
}
