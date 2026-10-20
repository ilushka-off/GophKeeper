// Package crypto implements GophKeeper cryptography: key derivation from the master
// password, AES-256-GCM encryption of records and chunked blobs, and password hashing
// for the server.
//
// The master password never leaves the client. Argon2id turns it into a master key,
// and HKDF splits the master key into two independent values: the login password that
// is sent to the server and the encryption key that stays on the client.
package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SaltSize is the size of a KDF salt in bytes.
const SaltSize = 16

// KeySize is the size of derived keys in bytes (AES-256).
const KeySize = 32

const (
	infoAuth = "gophkeeper/v1/auth"
	infoEnc  = "gophkeeper/v1/encryption"
)

// ErrInvalidSalt is returned when a KDF salt has a wrong size.
var ErrInvalidSalt = errors.New("crypto: invalid salt")

// KDFParams are Argon2id cost parameters.
type KDFParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultKDFParams follow the OWASP recommendation for Argon2id.
var DefaultKDFParams = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Keys are the values derived from the master password.
type Keys struct {
	// Auth is the login password material sent to the server.
	Auth []byte
	// Enc is the encryption key. It never leaves the client.
	Enc []byte
}

// NewSalt returns a random KDF salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypto: generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKeys derives the login password and the encryption key from the master password.
func DeriveKeys(master string, salt []byte, p KDFParams) (Keys, error) {
	if len(salt) < SaltSize {
		return Keys{}, ErrInvalidSalt
	}
	mk := argon2.IDKey([]byte(master), salt, p.Time, p.Memory, p.Threads, KeySize)
	auth, err := hkdf.Expand(sha256.New, mk, infoAuth, KeySize)
	if err != nil {
		return Keys{}, fmt.Errorf("crypto: derive auth key: %w", err)
	}
	enc, err := hkdf.Expand(sha256.New, mk, infoEnc, KeySize)
	if err != nil {
		return Keys{}, fmt.Errorf("crypto: derive encryption key: %w", err)
	}
	return Keys{Auth: auth, Enc: enc}, nil
}

// AuthPassword returns the login password as a string suitable for the Register and Login calls.
func (k Keys) AuthPassword() string {
	return base64.RawStdEncoding.EncodeToString(k.Auth)
}
