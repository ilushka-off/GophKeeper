package protoconv

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

func TestTypeConversion(t *testing.T) {
	for _, rt := range model.RecordTypes {
		p := TypeToProto(rt)
		assert.NotEqual(t, pb.RecordType_RECORD_TYPE_UNSPECIFIED, p)
		assert.Equal(t, rt, TypeFromProto(p))
	}
	assert.Equal(t, pb.RecordType_RECORD_TYPE_UNSPECIFIED, TypeToProto("passport"))
	assert.Equal(t, model.RecordType(""), TypeFromProto(pb.RecordType_RECORD_TYPE_UNSPECIFIED))
	assert.Equal(t, model.RecordType(""), TypeFromProto(pb.RecordType(99)))
}

func TestRecordRoundTrip(t *testing.T) {
	r := model.Record{
		ID:        uuid.New(),
		Type:      model.TypeCard,
		Payload:   []byte("cipher"),
		Version:   3,
		Revision:  7,
		Deleted:   true,
		UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	got, err := RecordFromProto(RecordToProto(r))
	require.NoError(t, err)
	assert.Equal(t, r, got, "UserID is not transferred")

	list := RecordsToProto([]model.Record{r, r})
	assert.Len(t, list, 2)
	assert.Empty(t, RecordsToProto(nil))
}

func TestRecordFromProtoBadID(t *testing.T) {
	_, err := RecordFromProto(&pb.Record{Id: "bad"})
	require.ErrorIs(t, err, model.ErrInvalidArgument)
}

func TestTokensRoundTrip(t *testing.T) {
	tk := model.Tokens{
		AccessToken:     "a",
		RefreshToken:    "r",
		AccessExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	assert.Equal(t, tk, TokensFromProto(TokensToProto(tk)))
}
