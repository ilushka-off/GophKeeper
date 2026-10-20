// Package config loads the server configuration from command-line flags and
// environment variables. Environment variables take precedence over flags.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the server configuration.
type Config struct {
	// Address is the gRPC listen address.
	Address string
	// HTTPAddress is the listen address of the REST gateway with the OpenAPI spec.
	// Empty disables the gateway.
	HTTPAddress string
	// DatabaseDSN is the PostgreSQL connection string. Empty means in-memory storage.
	DatabaseDSN string
	// TLSCert and TLSKey are paths to the server certificate and private key.
	TLSCert string
	TLSKey  string
	// JWTSecret signs access tokens.
	JWTSecret string
	// AccessTTL and RefreshTTL are token lifetimes.
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	// MaxBlobSize limits one binary record in bytes.
	MaxBlobSize int64
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
	// LogLevel is debug, info, warn or error.
	LogLevel string
}

// Load parses args (without the program name) and the environment returned by getenv.
func Load(args []string, getenv func(string) string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)
	fs.StringVar(&c.Address, "a", ":3200", "gRPC listen address (env ADDRESS)")
	fs.StringVar(&c.HTTPAddress, "http-address", "", "REST gateway listen address, empty to disable (env HTTP_ADDRESS)")
	fs.StringVar(&c.DatabaseDSN, "d", "", "PostgreSQL DSN, empty for in-memory storage (env DATABASE_DSN)")
	fs.StringVar(&c.TLSCert, "tls-cert", "certs/server.crt", "TLS certificate file (env TLS_CERT)")
	fs.StringVar(&c.TLSKey, "tls-key", "certs/server.key", "TLS private key file (env TLS_KEY)")
	fs.StringVar(&c.JWTSecret, "jwt-secret", "", "secret for signing access tokens (env JWT_SECRET)")
	fs.DurationVar(&c.AccessTTL, "access-ttl", 15*time.Minute, "access token lifetime (env ACCESS_TTL)")
	fs.DurationVar(&c.RefreshTTL, "refresh-ttl", 30*24*time.Hour, "refresh token lifetime (env REFRESH_TTL)")
	fs.Int64Var(&c.MaxBlobSize, "max-blob-size", 100<<20, "max size of binary data in bytes (env MAX_BLOB_SIZE)")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", 10*time.Second, "graceful shutdown timeout (env SHUTDOWN_TIMEOUT)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "log level: debug, info, warn, error (env LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if getenv == nil {
		getenv = os.Getenv
	}
	strEnv := map[string]*string{
		"ADDRESS":      &c.Address,
		"HTTP_ADDRESS": &c.HTTPAddress,
		"DATABASE_DSN": &c.DatabaseDSN,
		"TLS_CERT":     &c.TLSCert,
		"TLS_KEY":      &c.TLSKey,
		"JWT_SECRET":   &c.JWTSecret,
		"LOG_LEVEL":    &c.LogLevel,
	}
	for k, p := range strEnv {
		if v := getenv(k); v != "" {
			*p = v
		}
	}
	durEnv := map[string]*time.Duration{
		"ACCESS_TTL":       &c.AccessTTL,
		"REFRESH_TTL":      &c.RefreshTTL,
		"SHUTDOWN_TIMEOUT": &c.ShutdownTimeout,
	}
	for k, p := range durEnv {
		if v := getenv(k); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("config: %s: %w", k, err)
			}
			*p = d
		}
	}
	if v := getenv("MAX_BLOB_SIZE"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("config: MAX_BLOB_SIZE: %w", err)
		}
		c.MaxBlobSize = n
	}
	return c, c.Validate()
}

// Validate checks the configuration.
func (c Config) Validate() error {
	switch {
	case c.Address == "":
		return errors.New("config: address is required")
	case c.HTTPAddress != "" && c.HTTPAddress == c.Address:
		return errors.New("config: gRPC and HTTP addresses must differ")
	case c.TLSCert == "" || c.TLSKey == "":
		return errors.New("config: TLS certificate and key are required")
	case c.AccessTTL <= 0 || c.RefreshTTL <= 0:
		return errors.New("config: token lifetimes must be positive")
	case c.MaxBlobSize <= 0:
		return errors.New("config: max blob size must be positive")
	}
	return nil
}
