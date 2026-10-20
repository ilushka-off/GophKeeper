package config

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(nil, env(nil))
	require.NoError(t, err)
	assert.Equal(t, ":3200", c.Address)
	assert.Empty(t, c.DatabaseDSN)
	assert.Empty(t, c.HTTPAddress, "gateway is disabled by default")
	assert.Equal(t, "certs/server.crt", c.TLSCert)
	assert.Equal(t, "certs/server.key", c.TLSKey)
	assert.Equal(t, 15*time.Minute, c.AccessTTL)
	assert.Equal(t, 30*24*time.Hour, c.RefreshTTL)
	assert.Equal(t, int64(100<<20), c.MaxBlobSize)
	assert.Equal(t, 10*time.Second, c.ShutdownTimeout)
	assert.Equal(t, "info", c.LogLevel)
}

func TestLoadNilGetenv(t *testing.T) {
	t.Setenv("ADDRESS", ":4000")
	c, err := Load(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, ":4000", c.Address)
}

func TestLoadFlagsAndEnv(t *testing.T) {
	args := []string{
		"-a", ":1", "-http-address", ":8", "-d", "dsn-flag", "-tls-cert", "c", "-tls-key", "k", "-jwt-secret", "s",
		"-access-ttl", "1m", "-refresh-ttl", "2h", "-max-blob-size", "10",
		"-shutdown-timeout", "3s", "-log-level", "debug",
	}
	c, err := Load(args, env(nil))
	require.NoError(t, err)
	assert.Equal(t, Config{
		Address: ":1", HTTPAddress: ":8", DatabaseDSN: "dsn-flag", TLSCert: "c", TLSKey: "k", JWTSecret: "s",
		AccessTTL: time.Minute, RefreshTTL: 2 * time.Hour, MaxBlobSize: 10,
		ShutdownTimeout: 3 * time.Second, LogLevel: "debug",
	}, c)

	c, err = Load(args, env(map[string]string{
		"ADDRESS": ":2", "HTTP_ADDRESS": ":9", "DATABASE_DSN": "dsn-env", "TLS_CERT": "ce", "TLS_KEY": "ke",
		"JWT_SECRET": "se", "LOG_LEVEL": "warn", "ACCESS_TTL": "5m", "REFRESH_TTL": "1h",
		"SHUTDOWN_TIMEOUT": "1s", "MAX_BLOB_SIZE": "20",
	}))
	require.NoError(t, err)
	assert.Equal(t, Config{
		Address: ":2", HTTPAddress: ":9", DatabaseDSN: "dsn-env", TLSCert: "ce", TLSKey: "ke", JWTSecret: "se",
		AccessTTL: 5 * time.Minute, RefreshTTL: time.Hour, MaxBlobSize: 20,
		ShutdownTimeout: time.Second, LogLevel: "warn",
	}, c, "env overrides flags")
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]struct {
		args []string
		env  map[string]string
	}{
		"unknown flag":     {args: []string{"-nope"}},
		"bad duration env": {env: map[string]string{"ACCESS_TTL": "x"}},
		"bad int env":      {env: map[string]string{"MAX_BLOB_SIZE": "x"}},
		"zero ttl":         {args: []string{"-access-ttl", "0s"}},
		"empty cert":       {args: []string{"-tls-cert", ""}},
		"zero blob":        {args: []string{"-max-blob-size", "0"}},
		"empty address":    {args: []string{"-a", ""}},
		"same addresses":   {args: []string{"-a", ":1", "-http-address", ":1"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(tt.args, env(tt.env))
			require.Error(t, err)
		})
	}
}

func TestLoadHelp(t *testing.T) {
	_, err := Load([]string{"-h"}, env(nil))
	require.ErrorIs(t, err, flag.ErrHelp)
}
