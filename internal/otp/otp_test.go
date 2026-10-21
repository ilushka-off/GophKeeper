package otp

import (
	"crypto/sha1" //nolint:gosec // RFC test vectors use SHA1
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 6238 appendix B test vectors (8 digits).
func TestCodeRFC6238(t *testing.T) {
	secrets := map[string]string{
		SHA1:   "12345678901234567890",
		SHA256: "12345678901234567890123456789012",
		SHA512: "1234567890123456789012345678901234567890123456789012345678901234",
	}
	cases := []struct {
		unix int64
		alg  string
		want string
	}{
		{59, SHA1, "94287082"},
		{59, SHA256, "46119246"},
		{59, SHA512, "90693936"},
		{1111111109, SHA1, "07081804"},
		{1111111111, SHA256, "67062674"},
		{1234567890, SHA512, "93441116"},
		{2000000000, SHA1, "69279037"},
		{20000000000, SHA256, "77737706"},
	}
	for _, c := range cases {
		p := Params{
			Secret:    base32.StdEncoding.EncodeToString([]byte(secrets[c.alg])),
			Algorithm: c.alg,
			Digits:    8,
		}
		code, left, err := p.Code(time.Unix(c.unix, 0))
		require.NoError(t, err)
		assert.Equal(t, c.want, code, "%s at %d", c.alg, c.unix)
		assert.Equal(t, time.Duration(30-c.unix%30)*time.Second, left)
	}
}

func TestHOTPRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314"}
	for i, w := range want {
		assert.Equal(t, w, HOTP([]byte("12345678901234567890"), uint64(i), 6, sha1.New))
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	p := Params{Secret: "jbsw y3dp-ehpk 3pxp", Algorithm: "sha256"}.Normalize()
	assert.Equal(t, "JBSWY3DPEHPK3PXP", p.Secret)
	assert.Equal(t, SHA256, p.Algorithm)
	assert.Equal(t, DefaultDigits, p.Digits)
	assert.Equal(t, DefaultPeriod, p.Period)
	require.NoError(t, p.Validate())

	bad := []Params{
		{Secret: "", Algorithm: SHA1, Digits: 6, Period: 30},
		{Secret: "!!!", Algorithm: SHA1, Digits: 6, Period: 30},
		{Secret: "JBSWY3DPEHPK3PXP", Algorithm: "MD5", Digits: 6, Period: 30},
		{Secret: "JBSWY3DPEHPK3PXP", Algorithm: SHA1, Digits: 5, Period: 30},
		{Secret: "JBSWY3DPEHPK3PXP", Algorithm: SHA1, Digits: 6, Period: 0},
	}
	for _, b := range bad {
		require.ErrorIs(t, b.Validate(), ErrInvalid, "%+v", b)
	}
	_, _, err := Params{Secret: "!!"}.Code(time.Now())
	require.ErrorIs(t, err, ErrInvalid)
}

func TestDecodeSecretPadding(t *testing.T) {
	a, err := DecodeSecret("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	b, err := DecodeSecret("jbswy3dpehpk3pxp====")
	require.NoError(t, err)
	assert.Equal(t, a, b)
}

func TestParseURI(t *testing.T) {
	p, err := ParseURI("otpauth://totp/GitHub:ilya?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256")
	require.NoError(t, err)
	assert.Equal(t, Params{Secret: "JBSWY3DPEHPK3PXP", Issuer: "GitHub", Account: "ilya",
		Algorithm: SHA256, Digits: 8, Period: 60}, p)

	p, err = ParseURI("otpauth://totp/ilya@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	require.NoError(t, err)
	assert.Equal(t, "Example", p.Issuer)
	assert.Equal(t, "ilya@example.com", p.Account)

	for _, raw := range []string{
		"https://example.com",
		"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc",
		"otpauth://totp/x",
		"::bad",
	} {
		_, err := ParseURI(raw)
		require.ErrorIs(t, err, ErrInvalid, raw)
	}
}
