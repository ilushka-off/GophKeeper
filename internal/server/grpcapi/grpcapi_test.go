package grpcapi_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/grpcapi"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

type clients struct {
	auth  pb.AuthServiceClient
	vault pb.VaultServiceClient
	sync  pb.SyncServiceClient
}

func setup(t *testing.T) clients {
	t.Helper()
	conn := testutil.StartServer(t).Dial(t)
	return clients{
		auth:  pb.NewAuthServiceClient(conn),
		vault: pb.NewVaultServiceClient(conn),
		sync:  pb.NewSyncServiceClient(conn),
	}
}

func salt() []byte { return []byte("0123456789abcdef") }

// register creates a user and returns a context authorized with its access token.
func register(t *testing.T, c clients, login string) (context.Context, *pb.Tokens) {
	t.Helper()
	resp, err := c.auth.Register(context.Background(), &pb.RegisterRequest{Login: login, Password: "pw", KdfSalt: salt()})
	require.NoError(t, err)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+resp.GetTokens().GetAccessToken())
	return ctx, resp.GetTokens()
}

func TestAuthFlow(t *testing.T) {
	ctx := context.Background()
	c := setup(t)

	reg, err := c.auth.Register(ctx, &pb.RegisterRequest{Login: "ilya", Password: "pw", KdfSalt: salt()})
	require.NoError(t, err)
	assert.Equal(t, salt(), reg.GetKdfSalt())
	assert.NotEmpty(t, reg.GetTokens().GetAccessToken())

	_, err = c.auth.Register(ctx, &pb.RegisterRequest{Login: "ilya", Password: "pw", KdfSalt: salt()})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	_, err = c.auth.Register(ctx, &pb.RegisterRequest{Login: "x", Password: "pw", KdfSalt: salt()})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	s, err := c.auth.GetSalt(ctx, &pb.GetSaltRequest{Login: "ilya"})
	require.NoError(t, err)
	assert.Equal(t, salt(), s.GetKdfSalt())

	login, err := c.auth.Login(ctx, &pb.LoginRequest{Login: "ilya", Password: "pw"})
	require.NoError(t, err)
	assert.Equal(t, salt(), login.GetKdfSalt())
	_, err = c.auth.Login(ctx, &pb.LoginRequest{Login: "ilya", Password: "bad"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	ref, err := c.auth.Refresh(ctx, &pb.RefreshRequest{RefreshToken: login.GetTokens().GetRefreshToken()})
	require.NoError(t, err)
	assert.NotEmpty(t, ref.GetTokens().GetRefreshToken())
	_, err = c.auth.Refresh(ctx, &pb.RefreshRequest{RefreshToken: login.GetTokens().GetRefreshToken()})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = c.auth.Logout(ctx, &pb.LogoutRequest{RefreshToken: ref.GetTokens().GetRefreshToken()})
	require.NoError(t, err)
	_, err = c.auth.Refresh(ctx, &pb.RefreshRequest{RefreshToken: ref.GetTokens().GetRefreshToken()})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthRequired(t *testing.T) {
	c := setup(t)
	tests := map[string]context.Context{
		"no token":   context.Background(),
		"not bearer": metadata.AppendToOutgoingContext(context.Background(), "authorization", "Basic abc"),
		"invalid":    metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer garbage"),
	}
	for name, ctx := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := c.vault.ListRecords(ctx, &pb.ListRecordsRequest{})
			assert.Equal(t, codes.Unauthenticated, status.Code(err))

			stream, err := c.vault.DownloadBlob(ctx, &pb.DownloadBlobRequest{BlobId: uuid.NewString()})
			require.NoError(t, err)
			_, err = stream.Recv()
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestSyncAndVault(t *testing.T) {
	c := setup(t)
	ctx, _ := register(t, c, "ilya")
	otherCtx, _ := register(t, c, "other")
	id := uuid.NewString()

	push, err := c.sync.Push(ctx, &pb.PushRequest{Changes: []*pb.Change{
		{Id: id, Type: pb.RecordType_RECORD_TYPE_CREDENTIALS, Payload: []byte("enc")},
	}})
	require.NoError(t, err)
	require.Len(t, push.GetAccepted(), 1)
	assert.Equal(t, id, push.GetAccepted()[0].GetId())
	assert.Equal(t, int64(1), push.GetAccepted()[0].GetVersion())
	assert.Equal(t, int64(1), push.GetRevision())

	conflict, err := c.sync.Push(ctx, &pb.PushRequest{Changes: []*pb.Change{
		{Id: id, Type: pb.RecordType_RECORD_TYPE_CREDENTIALS, Payload: []byte("stale")},
	}})
	require.NoError(t, err)
	require.Len(t, conflict.GetConflicts(), 1)
	assert.Equal(t, []byte("enc"), conflict.GetConflicts()[0].GetPayload())

	pull, err := c.sync.Pull(ctx, &pb.PullRequest{Since: 0})
	require.NoError(t, err)
	require.Len(t, pull.GetRecords(), 1)
	assert.Equal(t, pb.RecordType_RECORD_TYPE_CREDENTIALS, pull.GetRecords()[0].GetType())
	_, err = c.sync.Pull(ctx, &pb.PullRequest{Since: -1})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	got, err := c.vault.GetRecord(ctx, &pb.GetRecordRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, id, got.GetRecord().GetId())
	_, err = c.vault.GetRecord(otherCtx, &pb.GetRecordRequest{Id: id})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = c.vault.GetRecord(ctx, &pb.GetRecordRequest{Id: "bad"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	list, err := c.vault.ListRecords(ctx, &pb.ListRecordsRequest{})
	require.NoError(t, err)
	assert.Len(t, list.GetRecords(), 1)

	_, err = c.sync.Push(otherCtx, &pb.PushRequest{Changes: []*pb.Change{
		{Id: id, Type: pb.RecordType_RECORD_TYPE_TEXT, Payload: []byte("x"), BaseVersion: 1},
	}})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = c.sync.Push(ctx, &pb.PushRequest{Changes: []*pb.Change{{Id: "bad"}}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = c.sync.Push(ctx, &pb.PushRequest{Changes: []*pb.Change{{Id: uuid.NewString(), Payload: []byte("x")}}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "unspecified type")
}

func upload(t *testing.T, c clients, ctx context.Context, msgs ...*pb.UploadBlobRequest) (*pb.UploadBlobResponse, error) {
	t.Helper()
	stream, err := c.vault.UploadBlob(ctx)
	require.NoError(t, err)
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			break
		}
	}
	return stream.CloseAndRecv()
}

func idMsg(id string) *pb.UploadBlobRequest {
	return &pb.UploadBlobRequest{Data: &pb.UploadBlobRequest_BlobId{BlobId: id}}
}

func chunkMsg(b []byte) *pb.UploadBlobRequest {
	return &pb.UploadBlobRequest{Data: &pb.UploadBlobRequest_Chunk{Chunk: b}}
}

func TestBlobs(t *testing.T) {
	c := setup(t)
	ctx, _ := register(t, c, "ilya")
	otherCtx, _ := register(t, c, "other")
	blobID := uuid.NewString()

	resp, err := upload(t, c, ctx, idMsg(blobID), chunkMsg([]byte("hello ")), chunkMsg([]byte("world")))
	require.NoError(t, err)
	assert.Equal(t, int64(11), resp.GetSize())
	assert.Equal(t, blobID, resp.GetBlobId())

	_, err = upload(t, c, ctx, idMsg(blobID), chunkMsg([]byte("again")))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	_, err = upload(t, c, ctx)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no blob id")
	_, err = upload(t, c, ctx, idMsg("bad"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = upload(t, c, ctx, idMsg(uuid.NewString()), idMsg(uuid.NewString()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "id after id")

	read := func(ctx context.Context, id string) ([]byte, error) {
		stream, err := c.vault.DownloadBlob(ctx, &pb.DownloadBlobRequest{BlobId: id})
		require.NoError(t, err)
		var buf bytes.Buffer
		for {
			msg, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return buf.Bytes(), nil
			}
			if err != nil {
				return nil, err
			}
			buf.Write(msg.GetChunk())
		}
	}
	data, err := read(ctx, blobID)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))
	_, err = read(otherCtx, blobID)
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = read(ctx, "bad")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = c.vault.DeleteBlob(ctx, &pb.DeleteBlobRequest{BlobId: "bad"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = c.vault.DeleteBlob(ctx, &pb.DeleteBlobRequest{BlobId: blobID})
	require.NoError(t, err)
	_, err = read(ctx, blobID)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestToStatus(t *testing.T) {
	ctx := context.Background()
	assert.NoError(t, grpcapi.ToStatus(ctx, nil))
	tests := []struct {
		err  error
		code codes.Code
	}{
		{fmt.Errorf("x: %w", model.ErrInvalidArgument), codes.InvalidArgument},
		{model.ErrNotFound, codes.NotFound},
		{model.ErrAlreadyExists, codes.AlreadyExists},
		{model.ErrPermissionDenied, codes.PermissionDenied},
		{model.ErrUnauthenticated, codes.Unauthenticated},
		{context.Canceled, codes.Canceled},
		{context.DeadlineExceeded, codes.DeadlineExceeded},
		{status.Error(codes.Aborted, "kept"), codes.Aborted},
		{errors.New("password=secret in db error"), codes.Internal},
	}
	for _, tt := range tests {
		got := grpcapi.ToStatus(ctx, tt.err)
		assert.Equal(t, tt.code, status.Code(got), tt.err.Error())
	}
	internal := grpcapi.ToStatus(ctx, errors.New("password=secret"))
	assert.NotContains(t, internal.Error(), "secret", "internal details are hidden")
}

func TestRecovery(t *testing.T) {
	_, err := grpcapi.RecoveryUnaryInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{},
		func(context.Context, any) (any, error) { panic("boom") })
	assert.Equal(t, codes.Internal, status.Code(err))

	err = grpcapi.RecoveryStreamInterceptor()(nil, fakeStream{}, &grpc.StreamServerInfo{},
		func(any, grpc.ServerStream) error { panic("boom") })
	assert.Equal(t, codes.Internal, status.Code(err))
}

type fakeStream struct{ grpc.ServerStream }

func (fakeStream) Context() context.Context { return context.Background() }

func TestLogging(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	_, err := grpcapi.LoggingUnaryInterceptor(log)(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/Method"},
		func(context.Context, any) (any, error) { return nil, status.Error(codes.Internal, "x") })
	require.Error(t, err)
	assert.Contains(t, buf.String(), "level=ERROR")
	assert.Contains(t, buf.String(), "/svc/Method")

	buf.Reset()
	err = grpcapi.LoggingStreamInterceptor(log)(nil, fakeStream{}, &grpc.StreamServerInfo{FullMethod: "/svc/Stream"},
		func(any, grpc.ServerStream) error { return nil })
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "code=OK")
}

func TestUserIDContext(t *testing.T) {
	_, ok := grpcapi.UserIDFromContext(context.Background())
	assert.False(t, ok)
	id := uuid.New()
	got, ok := grpcapi.UserIDFromContext(grpcapi.WithUserID(context.Background(), id))
	assert.True(t, ok)
	assert.Equal(t, id, got)
}

func TestNewServerRegistersServices(t *testing.T) {
	s := testutil.StartServer(t)
	srv := grpcapi.NewServer(s.Services, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer srv.Stop()
	info := srv.GetServiceInfo()
	assert.Contains(t, info, "gophkeeper.v1.AuthService")
	assert.Contains(t, info, "gophkeeper.v1.VaultService")
	assert.Contains(t, info, "gophkeeper.v1.SyncService")
}
