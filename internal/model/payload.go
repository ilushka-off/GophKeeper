package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ilushka-off/GophKeeper/internal/otp"
)

// Payload is the plaintext content of a record: a name, free-form metadata and typed data.
// It is serialized with Marshal and encrypted before it leaves the client.
type Payload struct {
	Name string
	Meta string
	Data Data
}

// Data is the type-specific part of a payload.
type Data interface {
	// Type returns the record type the data belongs to.
	Type() RecordType
	// Validate checks the data and returns an error wrapping ErrInvalidArgument.
	Validate() error
}

// Credentials is a login/password pair.
type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Text is arbitrary text.
type Text struct {
	Content string `json:"content"`
}

// Binary describes arbitrary binary data. The content itself is stored as an encrypted blob.
type Binary struct {
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`
	BlobID   string `json:"blob_id"`
}

// Card is a bank card.
type Card struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

// OTP is a TOTP generator: the shared secret and parameters from the service.
type OTP struct {
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer,omitempty"`
	Account   string `json:"account,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
}

// Params returns the generator parameters with defaults filled in.
func (o OTP) Params() otp.Params {
	return otp.Params{
		Secret: o.Secret, Issuer: o.Issuer, Account: o.Account,
		Algorithm: o.Algorithm, Digits: o.Digits, Period: o.Period,
	}.Normalize()
}

// Code returns the current one-time code and how long it stays valid.
func (o OTP) Code(now time.Time) (string, time.Duration, error) {
	return o.Params().Code(now)
}

// Type implements Data.
func (OTP) Type() RecordType { return TypeOTP }

// Validate implements Data.
func (o OTP) Validate() error {
	if err := o.Params().Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return nil
}

// Type implements Data.
func (Credentials) Type() RecordType { return TypeCredentials }

// Type implements Data.
func (Text) Type() RecordType { return TypeText }

// Type implements Data.
func (Binary) Type() RecordType { return TypeBinary }

// Type implements Data.
func (Card) Type() RecordType { return TypeCard }

// Validate implements Data.
func (c Credentials) Validate() error {
	if c.Login == "" && c.Password == "" {
		return fmt.Errorf("%w: login or password is required", ErrInvalidArgument)
	}
	return nil
}

// Validate implements Data.
func (t Text) Validate() error {
	if t.Content == "" {
		return fmt.Errorf("%w: text is empty", ErrInvalidArgument)
	}
	return nil
}

// Validate implements Data.
func (b Binary) Validate() error {
	if b.BlobID == "" {
		return fmt.Errorf("%w: blob id is required", ErrInvalidArgument)
	}
	if b.Size < 0 {
		return fmt.Errorf("%w: negative size", ErrInvalidArgument)
	}
	return nil
}

var (
	expiryRe = regexp.MustCompile(`^(0[1-9]|1[0-2])/([0-9]{2})$`)
	cvvRe    = regexp.MustCompile(`^[0-9]{3,4}$`)
)

// Validate implements Data. The number must pass the Luhn check, the expiry must be MM/YY.
func (c Card) Validate() error {
	if !LuhnValid(c.Number) {
		return fmt.Errorf("%w: card number is invalid", ErrInvalidArgument)
	}
	if c.Expiry != "" && !expiryRe.MatchString(c.Expiry) {
		return fmt.Errorf("%w: expiry must be MM/YY", ErrInvalidArgument)
	}
	if c.CVV != "" && !cvvRe.MatchString(c.CVV) {
		return fmt.Errorf("%w: cvv must be 3 or 4 digits", ErrInvalidArgument)
	}
	return nil
}

// Expired reports whether the card expiry is before the month of now.
// A card without an expiry is never expired.
func (c Card) Expired(now time.Time) bool {
	m := expiryRe.FindStringSubmatch(c.Expiry)
	if m == nil {
		return false
	}
	month, _ := strconv.Atoi(m[1])
	year, _ := strconv.Atoi(m[2])
	end := time.Date(2000+year, time.Month(month)+1, 1, 0, 0, 0, 0, time.UTC)
	return !now.Before(end)
}

// NormalizeCardNumber removes spaces and dashes from a card number.
func NormalizeCardNumber(number string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(number)
}

// LuhnValid reports whether number (spaces and dashes allowed) passes the Luhn check.
func LuhnValid(number string) bool {
	number = NormalizeCardNumber(number)
	if len(number) < 12 || len(number) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		d := int(number[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// Validate checks the payload name and data.
func (p Payload) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidArgument)
	}
	if p.Data == nil {
		return fmt.Errorf("%w: data is required", ErrInvalidArgument)
	}
	return p.Data.Validate()
}

// Type returns the record type of the payload data.
func (p Payload) Type() RecordType {
	if p.Data == nil {
		return ""
	}
	return p.Data.Type()
}

type payloadJSON struct {
	Name string          `json:"name"`
	Meta string          `json:"meta,omitempty"`
	Type RecordType      `json:"type"`
	Data json.RawMessage `json:"data"`
}

// MarshalPayload serializes a payload to JSON before encryption.
func MarshalPayload(p Payload) ([]byte, error) {
	if p.Data == nil {
		return nil, fmt.Errorf("%w: data is required", ErrInvalidArgument)
	}
	data, err := json.Marshal(p.Data)
	if err != nil {
		return nil, fmt.Errorf("marshal data: %w", err)
	}
	return json.Marshal(payloadJSON{Name: p.Name, Meta: p.Meta, Type: p.Data.Type(), Data: data})
}

// UnmarshalPayload parses a payload serialized by MarshalPayload.
func UnmarshalPayload(b []byte) (Payload, error) {
	var raw payloadJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return Payload{}, fmt.Errorf("unmarshal payload: %w", err)
	}
	var data Data
	switch raw.Type {
	case TypeCredentials:
		data = &Credentials{}
	case TypeText:
		data = &Text{}
	case TypeBinary:
		data = &Binary{}
	case TypeCard:
		data = &Card{}
	case TypeOTP:
		data = &OTP{}
	default:
		return Payload{}, fmt.Errorf("%w: unknown record type %q", ErrInvalidArgument, raw.Type)
	}
	if err := json.Unmarshal(raw.Data, data); err != nil {
		return Payload{}, fmt.Errorf("unmarshal %s data: %w", raw.Type, err)
	}
	return Payload{Name: raw.Name, Meta: raw.Meta, Data: deref(data)}, nil
}

func deref(d Data) Data {
	switch v := d.(type) {
	case *Credentials:
		return *v
	case *Text:
		return *v
	case *Binary:
		return *v
	case *Card:
		return *v
	case *OTP:
		return *v
	}
	return d
}
