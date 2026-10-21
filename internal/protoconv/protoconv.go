// Package protoconv converts between protobuf messages and domain types.
// It is shared by the server handlers and the client.
package protoconv

import (
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

var typeToProto = map[model.RecordType]pb.RecordType{
	model.TypeCredentials: pb.RecordType_RECORD_TYPE_CREDENTIALS,
	model.TypeText:        pb.RecordType_RECORD_TYPE_TEXT,
	model.TypeBinary:      pb.RecordType_RECORD_TYPE_BINARY,
	model.TypeCard:        pb.RecordType_RECORD_TYPE_CARD,
	model.TypeOTP:         pb.RecordType_RECORD_TYPE_OTP,
}

// TypeToProto converts a domain record type to protobuf.
func TypeToProto(t model.RecordType) pb.RecordType {
	return typeToProto[t]
}

// TypeFromProto converts a protobuf record type to the domain type.
// It returns an empty type for unknown values.
func TypeFromProto(t pb.RecordType) model.RecordType {
	for k, v := range typeToProto {
		if v == t {
			return k
		}
	}
	return ""
}

// RecordToProto converts a domain record to protobuf.
func RecordToProto(r model.Record) *pb.Record {
	return &pb.Record{
		Id:        r.ID.String(),
		Type:      TypeToProto(r.Type),
		Payload:   r.Payload,
		Version:   r.Version,
		Revision:  r.Revision,
		Deleted:   r.Deleted,
		UpdatedAt: timestamppb.New(r.UpdatedAt),
	}
}

// RecordFromProto converts a protobuf record to the domain type.
func RecordFromProto(r *pb.Record) (model.Record, error) {
	id, err := uuid.Parse(r.GetId())
	if err != nil {
		return model.Record{}, fmt.Errorf("%w: record id: %w", model.ErrInvalidArgument, err)
	}
	return model.Record{
		ID:        id,
		Type:      TypeFromProto(r.GetType()),
		Payload:   r.GetPayload(),
		Version:   r.GetVersion(),
		Revision:  r.GetRevision(),
		Deleted:   r.GetDeleted(),
		UpdatedAt: r.GetUpdatedAt().AsTime(),
	}, nil
}

// RecordsToProto converts a slice of domain records.
func RecordsToProto(rs []model.Record) []*pb.Record {
	out := make([]*pb.Record, 0, len(rs))
	for _, r := range rs {
		out = append(out, RecordToProto(r))
	}
	return out
}

// TokensToProto converts a token pair to protobuf.
func TokensToProto(t model.Tokens) *pb.Tokens {
	return &pb.Tokens{
		AccessToken:     t.AccessToken,
		RefreshToken:    t.RefreshToken,
		AccessExpiresAt: timestamppb.New(t.AccessExpiresAt),
	}
}

// TokensFromProto converts a protobuf token pair to the domain type.
func TokensFromProto(t *pb.Tokens) model.Tokens {
	return model.Tokens{
		AccessToken:     t.GetAccessToken(),
		RefreshToken:    t.GetRefreshToken(),
		AccessExpiresAt: t.GetAccessExpiresAt().AsTime(),
	}
}
