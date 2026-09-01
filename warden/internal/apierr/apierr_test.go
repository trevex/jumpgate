package apierr_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/trevex/jumpgate/warden/internal/apierr"
)

func TestInternalRedactor(t *testing.T) {
	ic := apierr.NewInternalRedactor()
	run := func(retErr error) error {
		next := connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, retErr
		})
		_, err := ic.WrapUnary(next)(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		return err
	}

	// A CodeInternal error carrying raw driver text is redacted to a generic message.
	raw := connect.NewError(connect.CodeInternal, errors.New(`pq: duplicate key value violates unique constraint "users_email_key"`))
	got := run(raw)
	var ce *connect.Error
	if !errors.As(got, &ce) || ce.Code() != connect.CodeInternal {
		t.Fatalf("want CodeInternal error, got %v", got)
	}
	if ce.Message() != "internal error" {
		t.Fatalf("internal message not redacted: %q", ce.Message())
	}

	// A non-Internal (already-sanitized) code passes through unchanged.
	orig := connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	if got := run(orig); !errors.Is(got, orig) {
		t.Fatalf("non-internal error altered: %v", got)
	}

	// A nil error passes through.
	if got := run(nil); got != nil {
		t.Fatalf("nil error became %v", got)
	}
}
