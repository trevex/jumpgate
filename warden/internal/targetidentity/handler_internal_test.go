package targetidentity

import (
	"testing"

	"connectrpc.com/connect"
)

func TestHandlerDomainErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"stale revision", ErrStaleRevision, connect.CodeAborted},
		{"expectation mismatch", ErrExpectationMismatch, connect.CodeFailedPrecondition},
		{"unsupported evidence", ErrUnsupportedEvidence, connect.CodeFailedPrecondition},
		{"validation", ErrInvalidRequest, connect.CodeInvalidArgument},
		{"missing resource", ErrObservationNotFound, connect.CodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(domainError(tt.err)); got != tt.want {
				t.Fatalf("code = %v, want %v", got, tt.want)
			}
		})
	}
}
