// Package apierr provides the shared Connect error mapping used by the ConnectRPC
// handlers: Postgres write-error → Connect code translation and the common
// sentinel (pgx.ErrNoRows) → NotFound mappers. It is a transport leaf: it imports
// only connect, the pgx driver types, and stdlib, never a domain module.
package apierr

import (
	"errors"

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
	if _, ok := err.(*connect.Error); ok {
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
