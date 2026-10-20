package model

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordTypeValid(t *testing.T) {
	for _, rt := range RecordTypes {
		assert.True(t, rt.Valid(), rt)
	}
	assert.False(t, RecordType("").Valid())
	assert.False(t, RecordType("otp").Valid())
}

func TestPayloadRoundTrip(t *testing.T) {
	tests := []Payload{
		{Name: "github", Meta: "https://github.com", Data: Credentials{Login: "ilya", Password: "p@ss"}},
		{Name: "note", Data: Text{Content: "hello\nworld"}},
		{Name: "photo", Meta: "jpeg", Data: Binary{FileName: "a.jpg", Size: 42, BlobID: "b1"}},
		{Name: "visa", Data: Card{Number: "4111111111111111", Holder: "ILYA", Expiry: "12/30", CVV: "123"}},
	}
	for _, p := range tests {
		t.Run(string(p.Type()), func(t *testing.T) {
			b, err := MarshalPayload(p)
			require.NoError(t, err)
			got, err := UnmarshalPayload(b)
			require.NoError(t, err)
			assert.Equal(t, p, got)
			assert.Equal(t, p.Data.Type(), got.Type())
			require.NoError(t, got.Validate())
		})
	}
}

func TestMarshalPayloadNilData(t *testing.T) {
	_, err := MarshalPayload(Payload{Name: "x"})
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.Equal(t, RecordType(""), Payload{}.Type())
}

func TestUnmarshalPayloadErrors(t *testing.T) {
	tests := map[string]string{
		"not json":     `{`,
		"unknown type": `{"name":"x","type":"otp","data":{}}`,
		"bad data":     `{"name":"x","type":"text","data":{"content":1}}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalPayload([]byte(in))
			require.Error(t, err)
		})
	}
	_, err := UnmarshalPayload([]byte(`{"name":"x","type":"otp","data":{}}`))
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestPayloadValidate(t *testing.T) {
	tests := []struct {
		name string
		p    Payload
		ok   bool
	}{
		{"ok", Payload{Name: "a", Data: Text{Content: "x"}}, true},
		{"empty name", Payload{Name: "  ", Data: Text{Content: "x"}}, false},
		{"nil data", Payload{Name: "a"}, false},
		{"creds login only", Payload{Name: "a", Data: Credentials{Login: "l"}}, true},
		{"creds password only", Payload{Name: "a", Data: Credentials{Password: "p"}}, true},
		{"creds empty", Payload{Name: "a", Data: Credentials{}}, false},
		{"text empty", Payload{Name: "a", Data: Text{}}, false},
		{"binary ok", Payload{Name: "a", Data: Binary{BlobID: "b", Size: 0}}, true},
		{"binary no blob", Payload{Name: "a", Data: Binary{Size: 1}}, false},
		{"binary negative", Payload{Name: "a", Data: Binary{BlobID: "b", Size: -1}}, false},
		{"card ok", Payload{Name: "a", Data: Card{Number: "4111 1111 1111 1111"}}, true},
		{"card bad luhn", Payload{Name: "a", Data: Card{Number: "4111111111111112"}}, false},
		{"card bad expiry", Payload{Name: "a", Data: Card{Number: "4111111111111111", Expiry: "13/30"}}, false},
		{"card bad expiry fmt", Payload{Name: "a", Data: Card{Number: "4111111111111111", Expiry: "1/30"}}, false},
		{"card bad cvv", Payload{Name: "a", Data: Card{Number: "4111111111111111", CVV: "12"}}, false},
		{"card cvv letters", Payload{Name: "a", Data: Card{Number: "4111111111111111", CVV: "12a"}}, false},
		{"card 4 digit cvv", Payload{Name: "a", Data: Card{Number: "378282246310005", CVV: "1234", Expiry: "01/29"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidArgument))
		})
	}
}

func TestLuhnValid(t *testing.T) {
	tests := map[string]bool{
		"4111111111111111":     true,
		"4111-1111-1111-1111":  true,
		"5555555555554444":     true,
		"378282246310005":      true,
		"4111111111111112":     false,
		"41111111111":          false, // too short
		"41111111111111111111": false, // too long
		"411111111111111a":     false,
		"":                     false,
	}
	for in, want := range tests {
		assert.Equal(t, want, LuhnValid(in), in)
	}
}

func TestNormalizeCardNumber(t *testing.T) {
	assert.Equal(t, "4111111111111111", NormalizeCardNumber("4111 1111-1111 1111"))
}

func TestCardExpired(t *testing.T) {
	now := time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)
	tests := map[string]bool{
		"":      false,
		"bad":   false,
		"10/26": false, // valid through the end of the month
		"09/26": true,
		"11/26": false,
		"12/25": true,
		"01/30": false,
	}
	for exp, want := range tests {
		assert.Equal(t, want, Card{Expiry: exp}.Expired(now), exp)
	}
}

func TestDataTypes(t *testing.T) {
	assert.Equal(t, TypeCredentials, Credentials{}.Type())
	assert.Equal(t, TypeText, Text{}.Type())
	assert.Equal(t, TypeBinary, Binary{}.Type())
	assert.Equal(t, TypeCard, Card{}.Type())
}

type otherData struct{}

func (otherData) Type() RecordType { return "other" }
func (otherData) Validate() error  { return nil }

func TestDerefUnknown(t *testing.T) {
	d := otherData{}
	assert.Equal(t, Data(d), deref(d))
}

func TestPayloadJSONShape(t *testing.T) {
	b, err := MarshalPayload(Payload{Name: "n", Data: Text{Content: "c"}})
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	assert.Equal(t, "text", raw["type"])
	assert.NotContains(t, raw, "meta")
}
