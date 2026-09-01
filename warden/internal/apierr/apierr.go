// Package apierr provides the shared Connect error mapping used by the ConnectRPC
// handlers: Postgres write-error → Connect code translation and the common
// sentinel (pgx.ErrNoRows) → NotFound mappers. It is a transport leaf: it imports
// only connect, the pgx driver types, and stdlib, never a domain module.
package apierr

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL SQLSTATE codes used to map DB constraint failures to Connect codes.
const (
	pgerrcodeUniqueViolation     = "23505"
	pgerrcodeForeignKeyViolation = "23503"
	pgerrcodeCheckViolation      = "23514"
)

// MapWrite maps a Postgres write error to an appropriate Connect code so that
// bad client input (a reference to a non-existent role/scope/subject, a violated
// constraint) surfaces as InvalidArgument/AlreadyExists rather than Internal.
// Returns nil for a nil error.
func MapWrite(err error) error {
	if err == nil {
		return nil
	}
	// A pre-mapped Connect error (e.g. an InvalidArgument from login validation)
	// passes through unchanged rather than being masked as Internal.
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcodeUniqueViolation:
			return connect.NewError(connect.CodeAlreadyExists, errors.New("already exists"))
		case pgerrcodeForeignKeyViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("references a non-existent entity"))
		case pgerrcodeCheckViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("violates a constraint"))
		}
	}
	return connect.NewError(connect.CodeInternal, err)
}

// errInternal is the message clients see for any CodeInternal error, so raw
// driver/internal text (Postgres constraint names, SQL fragments, host details)
// never crosses the wire.
var errInternal = errors.New("internal error")

// NewInternalRedactor returns an interceptor that redacts the message of any
// outgoing CodeInternal error to a generic string, logging the real error
// server-side (keyed by procedure) so debuggability is preserved. It is the
// single boundary guard for the whole handler set: individual handlers may keep
// wrapping CodeInternal with a raw error for logging; this ensures the client only
// ever sees "internal error". Non-Internal codes (InvalidArgument, NotFound,
// PermissionDenied, …) are already-sanitized domain signals and pass through
// unchanged. Streaming RPCs pass through (UnaryInterceptorFunc), which is
// sufficient: the user-facing API is unary; streaming lives on the mTLS mesh.
func NewInternalRedactor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			if err == nil {
				return resp, nil
			}
			var ce *connect.Error
			if errors.As(err, &ce) && ce.Code() == connect.CodeInternal {
				slog.Error("internal rpc error", "procedure", req.Spec().Procedure, "err", err)
				return resp, connect.NewError(connect.CodeInternal, errInternal)
			}
			return resp, err
		}
	})
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcodeUniqueViolation
}

// RoleNotFoundOrInternal maps pgx.ErrNoRows to NotFound and anything else to Internal.
func RoleNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such role"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// GroupNotFoundOrInternal maps pgx.ErrNoRows to NotFound and anything else to Internal.
func GroupNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return connect.NewError(connect.CodeInternal, err)
}
