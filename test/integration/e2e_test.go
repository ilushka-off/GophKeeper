//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
)

const (
	master   = "correct horse battery staple"
	password = "s3cret-pass-%42"
)

// TestEndToEnd walks a user through two devices: registration, all record types,
// sync, conflicts, binary data, deletion and blob garbage collection.
func TestEndToEnd(t *testing.T) {
	// A short access token lifetime makes the client refresh tokens during the test.
	srv := startServer(t, 2*time.Second)
	login := uniqueLogin("ilya")

	laptop := newDevice(t, srv, master)
	assert.Contains(t, laptop.ok("register", "-l", login), "Registered as "+login)
	assert.Contains(t, newDevice(t, srv, master).fail("register", "-l", login), "already exists")

	// All record types on the first device.
	credID := laptop.add("credentials", "-n", "GitHub", "--login", "ilya", "--password", password, "-m", "https://github.com")
	textID := laptop.add("text", "-n", "note", "--text", "plaintext note")
	cardID := laptop.add("card", "-n", "visa", "--number", "4111 1111 1111 1111",
		"--holder", "ILYA", "--expiry", "12/30", "--cvv", "123")
	binPath, binData := randomFile(t, "photo.jpg", crypto.ChunkSize*2+777)
	binID := laptop.add("binary", "-n", "photo", "--file", binPath)
	otpID := laptop.add("otp", "--uri", "otpauth://totp/GitLab:ilya?secret=JBSWY3DPEHPK3PXP")
	assert.Contains(t, laptop.ok("status"), "Pending: 0")

	// The server stores only ciphertext.
	assert.Equal(t, 5, count(t,
		`SELECT COUNT(*) FROM records r JOIN users u ON u.id = r.user_id WHERE u.login = $1`, login))
	db(t, func(ctx context.Context, conn *pgx.Conn) {
		rows, err := conn.Query(ctx,
			`SELECT r.payload FROM records r JOIN users u ON u.id = r.user_id WHERE u.login = $1`, login)
		require.NoError(t, err)
		payloads, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		require.NoError(t, err)
		for _, p := range payloads {
			for _, secret := range []string{password, "plaintext note", "4111", "JBSWY3DPEHPK3PXP", "GitHub"} {
				assert.False(t, bytes.Contains(p, []byte(secret)), "server sees %q", secret)
			}
		}
	})
	assert.Equal(t, 1, countBlobs(t, login))
	assert.Equal(t, 3, count(t,
		`SELECT COUNT(*) FROM blob_chunks c JOIN blobs b ON b.id = c.blob_id JOIN users u ON u.id = b.user_id
		 WHERE u.login = $1`, login))

	// Second device: a wrong master password does not log in, the right one downloads everything.
	phone := newDevice(t, srv, master)
	phone.withMaster("wrong master password").fail("login", "-l", login)
	assert.Contains(t, phone.ok("login", "-l", login), "Synced 5 change(s)")
	list := phone.ok("list")
	for _, name := range []string{"GitHub", "note", "visa", "photo", "GitLab"} {
		assert.Contains(t, list, name)
	}
	assert.Contains(t, phone.ok("get", credID), password)
	assert.Contains(t, phone.ok("get", cardID), "4111111111111111")
	assert.Regexp(t, `Code:\s+\d{6} \(valid \d+s\)`, phone.ok("get", otpID))
	outPath := filepath.Join(t.TempDir(), "photo.out")
	assert.Contains(t, phone.ok("get", binID, "--out", outPath), "Saved")
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, binData, got)

	// The local vault cannot be opened with a wrong master password.
	assert.Contains(t, laptop.withMaster("wrong master password").fail("list"), "wrong master password")

	// An edit on one device reaches the other; the access token has expired by now.
	time.Sleep(2500 * time.Millisecond)
	phone.ok("edit", textID, "--text", "edited on phone")
	assert.Contains(t, laptop.ok("sync"), "pulled 1")
	assert.Contains(t, laptop.ok("get", textID), "edited on phone")

	// Concurrent edits: the server version wins, the local one is kept as a conflict copy.
	offline := laptop.offline()
	_, errOut, code := offline.run("edit", credID, "--password", "laptop-pass")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, errOut, "saved locally, sync failed")
	phone.ok("edit", credID, "--password", "phone-pass")
	assert.Contains(t, laptop.ok("sync"), "conflicts 1")
	assert.Contains(t, laptop.ok("get", credID), "phone-pass")
	assert.Contains(t, laptop.ok("list"), "(conflict")
	phone.ok("sync")
	assert.Contains(t, phone.ok("list"), "(conflict")

	// Replacing the file uploads a new blob; the old one is removed from the server.
	smallPath, smallData := randomFile(t, "small.bin", 100)
	phone.ok("edit", binID, "--file", smallPath)
	laptop.ok("sync")
	laptop.ok("get", binID, "--out", outPath)
	got, err = os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, smallData, got)
	assert.Equal(t, 1, countBlobs(t, login))

	// Deletion propagates and the blob is collected.
	assert.Contains(t, laptop.ok("delete", binID), "Deleted")
	phone.ok("sync")
	assert.NotContains(t, phone.ok("list"), "photo")
	assert.Contains(t, phone.fail("get", binID), "not found")
	assert.Zero(t, countBlobs(t, login))

	// Logout ends the session on the device only.
	assert.Contains(t, laptop.ok("logout"), "Logged out")
	assert.Contains(t, laptop.fail("sync"), "not logged in")
	phone.ok("sync")

	// Graceful shutdown: the server stops cleanly and clients report it as unavailable.
	require.NoError(t, srv.stop())
	phone.fail("sync")
	assert.Contains(t, phone.ok("get", textID), "edited on phone", "local data stays readable offline")
}

// TestUsersAreIsolated checks that a user never sees another user's records.
func TestUsersAreIsolated(t *testing.T) {
	srv := startServer(t, time.Minute)
	alice := newDevice(t, srv, master)
	alice.ok("register", "-l", uniqueLogin("alice"))
	id := alice.add("text", "-n", "alice secret", "--text", "for alice only")

	bob := newDevice(t, srv, "another master password")
	bob.ok("register", "-l", uniqueLogin("bob"))
	assert.Contains(t, bob.ok("list"), "No records.")
	assert.Contains(t, bob.fail("get", id), "not found")
	bob.ok("sync")
	assert.Contains(t, bob.ok("list"), "No records.")
}

func countBlobs(t *testing.T, login string) int {
	t.Helper()
	return count(t, `SELECT COUNT(*) FROM blobs b JOIN users u ON u.id = b.user_id WHERE u.login = $1`, login)
}
