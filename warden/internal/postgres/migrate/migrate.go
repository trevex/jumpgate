// Package migrate applies the embedded goose SQL migrations to Postgres, interleaved
// with the Go-based migrations that need logic SQL cannot express safely.
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx" for goose
	"github.com/pressly/goose/v3"

	"github.com/trevex/jumpgate/warden/internal/postgres/migrate/migrations"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// newProvider builds the goose provider over the embedded SQL migrations plus the
// registered Go migrations. Goose runs both sets strictly in version order.
func newProvider(db *sql.DB) (*goose.Provider, error) {
	fsys, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sub fs: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithGoMigrations(migrations.GoMigrations()...))
	if err != nil {
		return nil, fmt.Errorf("goose provider: %w", err)
	}
	return provider, nil
}

// Up applies all pending migrations to the database at dsn.
func Up(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()

	provider, err := newProvider(db)
	if err != nil {
		return err
	}
	if _, err := provider.Up(context.Background()); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
