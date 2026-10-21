// Package otp generates time-based one-time passwords (TOTP, RFC 6238) and parses
// otpauth:// URIs used by authenticator apps.
package otp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the TOTP default required by RFC 6238
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Supported hash algorithms.
const (
	SHA1   = "SHA1"
	SHA256 = "SHA256"
	SHA512 = "SHA512"
)

// Defaults used by most authenticator apps.
const (
	DefaultDigits = 6
	DefaultPeriod = 30
)

// ErrInvalid is returned for a malformed secret, URI or parameter.
var ErrInvalid = errors.New("otp: invalid parameters")

// Params describe a TOTP generator.
type Params struct {
	// Secret is the shared secret in base32, as shown by services.
	Secret    string
	Issuer    string
	Account   string
	Algorithm string
	Digits    int
	Period    int
}

// Normalize fills defaults and canonicalizes the secret and algorithm.
func (p Params) Normalize() Params {
	p.Secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(p.Secret))
	p.Algorithm = strings.ToUpper(p.Algorithm)
	if p.Algorithm == "" {
		p.Algorithm = SHA1
	}
	if p.Digits == 0 {
		p.Digits = DefaultDigits
	}
	if p.Period == 0 {
		p.Period = DefaultPeriod
	}
	return p
}

// Validate checks the parameters after Normalize.
func (p Params) Validate() error {
	if _, err := DecodeSecret(p.Secret); err != nil {
		return err
	}
	if _, err := hasher(p.Algorithm); err != nil {
		return err
	}
	if p.Digits < 6 || p.Digits > 8 {
		return fmt.Errorf("%w: digits must be 6..8", ErrInvalid)
	}
	if p.Period < 1 || p.Period > 300 {
		return fmt.Errorf("%w: period must be 1..300 seconds", ErrInvalid)
	}
	return nil
}

// DecodeSecret decodes a base32 secret with or without padding.
func DecodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "="))
	if s == "" {
		return nil, fmt.Errorf("%w: secret is empty", ErrInvalid)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: secret is not base32", ErrInvalid)
	}
	return key, nil
}

func hasher(alg string) (func() hash.Hash, error) {
	switch alg {
	case SHA1:
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalid, alg)
}

// Code returns the TOTP code for time t and how long it stays valid.
func (p Params) Code(t time.Time) (string, time.Duration, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return "", 0, err
	}
	key, _ := DecodeSecret(p.Secret)
	h, _ := hasher(p.Algorithm)
	unix := t.Unix()
	counter := uint64(unix / int64(p.Period)) //nolint:gosec // time after 1970 is never negative here
	code := HOTP(key, counter, p.Digits, h)
	left := time.Duration(int64(p.Period)-unix%int64(p.Period)) * time.Second
	return code, left, nil
}

// HOTP computes an HMAC-based one-time password (RFC 4226).
func HOTP(key []byte, counter uint64, digits int, h func() hash.Hash) string {
	mac := hmac.New(h, key)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// ParseURI parses an otpauth://totp/Issuer:account?secret=...&issuer=... URI.
func ParseURI(raw string) (Params, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "otpauth" {
		return Params{}, fmt.Errorf("%w: not an otpauth URI", ErrInvalid)
	}
	if u.Host != "totp" {
		return Params{}, fmt.Errorf("%w: only totp is supported", ErrInvalid)
	}
	q := u.Query()
	p := Params{Secret: q.Get("secret"), Issuer: q.Get("issuer"), Algorithm: q.Get("algorithm")}
	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		if p.Issuer == "" {
			p.Issuer = issuer
		}
		p.Account = strings.TrimSpace(account)
	} else {
		p.Account = label
	}
	for key, dst := range map[string]*int{"digits": &p.Digits, "period": &p.Period} {
		if v := q.Get(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return Params{}, fmt.Errorf("%w: %s", ErrInvalid, key)
			}
			*dst = n
		}
	}
	p = p.Normalize()
	return p, p.Validate()
}
