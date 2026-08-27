// Package authz is Jumpgate's stable public authorization API: the Authorizer
// interface and the capability/scope vocabulary (CapMatch, Scope, capability
// normalization). It is the ONE non-internal library package in warden — all
// other domain logic lives under internal/.
//
// The concrete, persistence-backed Authorizer lives in internal/authz and is
// intentionally private, so this package never exposes database models, pgx, or
// sqlc types as public API. Callers depend on the interface; the implementation
// (PostgreSQL SQL functions consumed via sqlc) can change without breaking them.
package authz
