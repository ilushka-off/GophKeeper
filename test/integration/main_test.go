//go:build integration

// Package integration contains end-to-end tests: the real server over TLS with PostgreSQL
// and the command-line client on several devices.
//
// PostgreSQL is taken from TEST_DATABASE_DSN when it is set, otherwise it is started
// in a Docker container with testcontainers. Run with: make test-integration.
package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// dsn is the PostgreSQL connection string shared by all tests.
var dsn string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()
	dsn = os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
			tcpostgres.WithDatabase("gophkeeper"),
			tcpostgres.WithUsername("gophkeeper"),
			tcpostgres.WithPassword("gophkeeper"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(time.Minute)),
		)
		if err != nil {
			log.Printf("start PostgreSQL container (set TEST_DATABASE_DSN to use an existing database): %v", err)
			return 1
		}
		defer func() {
			if err := testcontainers.TerminateContainer(ctr); err != nil {
				log.Printf("terminate container: %v", err)
			}
		}()
		dsn, err = ctr.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			log.Printf("container DSN: %v", err)
			return 1
		}
	}
	if err := resetDB(ctx, dsn); err != nil {
		log.Print(err)
		return 1
	}
	return m.Run()
}

// resetDB drops the schema so every run starts from an empty database and applies the real migrations.
func resetDB(ctx context.Context, dsn string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx,
		`DROP TABLE IF EXISTS blob_chunks, blobs, records, refresh_tokens, users, goose_db_version CASCADE`)
	if err != nil {
		return fmt.Errorf("reset database: %w", err)
	}
	return nil
}
