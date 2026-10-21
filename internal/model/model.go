// Package model describes the domain types shared by the GophKeeper server and client:
// users, encrypted records, sync changes and the plaintext payloads of the four record types.
package model

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Domain errors returned by storages and services.
var (
	// ErrNotFound means the requested entity does not exist or belongs to another user.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists means an entity with the same unique key already exists.
	ErrAlreadyExists = errors.New("already exists")
	// ErrPermissionDenied means the entity belongs to another user.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrInvalidArgument means the input failed validation.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrUnauthenticated means credentials or tokens are wrong or expired.
	ErrUnauthenticated = errors.New("unauthenticated")
)

// RecordType is the kind of private data stored in a record.
type RecordType string

// Supported record types.
const (
	TypeCredentials RecordType = "credentials"
	TypeText        RecordType = "text"
	TypeBinary      RecordType = "binary"
	TypeCard        RecordType = "card"
	TypeOTP         RecordType = "otp"
)

// RecordTypes lists all supported record types in display order.
var RecordTypes = []RecordType{TypeCredentials, TypeText, TypeBinary, TypeCard, TypeOTP}

// Valid reports whether t is one of the supported record types.
func (t RecordType) Valid() bool {
	switch t {
	case TypeCredentials, TypeText, TypeBinary, TypeCard, TypeOTP:
		return true
	}
	return false
}

// User is a registered GophKeeper user.
type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	KDFSalt      []byte
	Revision     int64
	CreatedAt    time.Time
}

// Record is an encrypted record. The server never sees Payload in plaintext.
type Record struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Type      RecordType
	Payload   []byte
	Version   int64
	Revision  int64
	Deleted   bool
	UpdatedAt time.Time
}

// Change is a modification a client pushes to the server.
type Change struct {
	ID          uuid.UUID
	Type        RecordType
	Payload     []byte
	Deleted     bool
	BaseVersion int64
}

// Accepted describes a change applied by the server.
type Accepted struct {
	ID       uuid.UUID
	Version  int64
	Revision int64
}

// PushResult is the outcome of a push: applied changes and conflicting server records.
type PushResult struct {
	Accepted  []Accepted
	Conflicts []Record
	Revision  int64
}

// RefreshToken is a stored refresh token. Only the hash of the token is kept.
type RefreshToken struct {
	Hash      []byte
	UserID    uuid.UUID
	ExpiresAt time.Time
}

// Tokens is a pair of access and refresh tokens issued to a client.
type Tokens struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
}
