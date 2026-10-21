package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/protoconv"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
)

// AuthHandler implements pb.AuthServiceServer.
type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	auth *service.Auth
}

// VaultHandler implements pb.VaultServiceServer.
type VaultHandler struct {
	pb.UnimplementedVaultServiceServer
	vault *service.Vault
}

// SyncHandler implements pb.SyncServiceServer.
type SyncHandler struct {
	pb.UnimplementedSyncServiceServer
	sync *service.Sync
}

// Services groups the business services the gRPC server exposes.
type Services struct {
	Auth  *service.Auth
	Vault *service.Vault
	Sync  *service.Sync
}

// NewServer creates a gRPC server with all GophKeeper services and interceptors registered.
// opts are appended to the default options, e.g. grpc.Creds for TLS.
func NewServer(s Services, log *slog.Logger, opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			LoggingUnaryInterceptor(log),
			RecoveryUnaryInterceptor(),
			AuthUnaryInterceptor(s.Auth),
		),
		grpc.ChainStreamInterceptor(
			LoggingStreamInterceptor(log),
			RecoveryStreamInterceptor(),
			AuthStreamInterceptor(s.Auth),
		),
		grpc.MaxRecvMsgSize(4 << 20),
	}
	srv := grpc.NewServer(append(base, opts...)...)
	pb.RegisterAuthServiceServer(srv, &AuthHandler{auth: s.Auth})
	pb.RegisterVaultServiceServer(srv, &VaultHandler{vault: s.Vault})
	pb.RegisterSyncServiceServer(srv, &SyncHandler{sync: s.Sync})
	return srv
}

// Register implements pb.AuthServiceServer.
func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	t, err := h.auth.Register(ctx, req.GetLogin(), req.GetPassword(), req.GetKdfSalt())
	if errors.Is(err, model.ErrAlreadyExists) {
		return nil, status.Error(codes.AlreadyExists, "login is already taken")
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.RegisterResponse{Tokens: protoconv.TokensToProto(t), KdfSalt: req.GetKdfSalt()}, nil
}

// GetSalt implements pb.AuthServiceServer.
func (h *AuthHandler) GetSalt(ctx context.Context, req *pb.GetSaltRequest) (*pb.GetSaltResponse, error) {
	salt, err := h.auth.GetSalt(ctx, req.GetLogin())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.GetSaltResponse{KdfSalt: salt}, nil
}

// Login implements pb.AuthServiceServer.
func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	t, salt, err := h.auth.Login(ctx, req.GetLogin(), req.GetPassword())
	if errors.Is(err, model.ErrUnauthenticated) {
		return nil, status.Error(codes.Unauthenticated, "wrong login or password")
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.LoginResponse{Tokens: protoconv.TokensToProto(t), KdfSalt: salt}, nil
}

// Refresh implements pb.AuthServiceServer.
func (h *AuthHandler) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	t, err := h.auth.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.RefreshResponse{Tokens: protoconv.TokensToProto(t)}, nil
}

// Logout implements pb.AuthServiceServer.
func (h *AuthHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if err := h.auth.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.LogoutResponse{}, nil
}

// GetRecord implements pb.VaultServiceServer.
func (h *VaultHandler) GetRecord(ctx context.Context, req *pb.GetRecordRequest) (*pb.GetRecordResponse, error) {
	uid, err := userID(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseID(req.GetId(), "record id")
	if err != nil {
		return nil, err
	}
	r, err := h.vault.GetRecord(ctx, uid, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.GetRecordResponse{Record: protoconv.RecordToProto(r)}, nil
}

// ListRecords implements pb.VaultServiceServer.
func (h *VaultHandler) ListRecords(ctx context.Context, _ *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
	uid, err := userID(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := h.vault.ListRecords(ctx, uid)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.ListRecordsResponse{Records: protoconv.RecordsToProto(rs)}, nil
}

// UploadBlob implements pb.VaultServiceServer.
func (h *VaultHandler) UploadBlob(stream grpc.ClientStreamingServer[pb.UploadBlobRequest, pb.UploadBlobResponse]) error {
	ctx := stream.Context()
	uid, err := userID(ctx)
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "blob id is required")
	}
	blobID, err := parseID(first.GetBlobId(), "blob id")
	if err != nil {
		return err
	}
	next := func() ([]byte, error) {
		msg, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		chunk, ok := msg.GetData().(*pb.UploadBlobRequest_Chunk)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "only chunks may follow the blob id")
		}
		return chunk.Chunk, nil
	}
	size, err := h.vault.UploadBlob(ctx, uid, blobID, next)
	if err != nil {
		return toStatus(ctx, err)
	}
	return stream.SendAndClose(&pb.UploadBlobResponse{BlobId: blobID.String(), Size: size})
}

// DownloadBlob implements pb.VaultServiceServer.
func (h *VaultHandler) DownloadBlob(req *pb.DownloadBlobRequest, stream grpc.ServerStreamingServer[pb.DownloadBlobResponse]) error {
	ctx := stream.Context()
	uid, err := userID(ctx)
	if err != nil {
		return err
	}
	blobID, err := parseID(req.GetBlobId(), "blob id")
	if err != nil {
		return err
	}
	err = h.vault.DownloadBlob(ctx, uid, blobID, func(chunk []byte) error {
		return stream.Send(&pb.DownloadBlobResponse{Chunk: chunk})
	})
	return toStatus(ctx, err)
}

// DeleteBlob implements pb.VaultServiceServer.
func (h *VaultHandler) DeleteBlob(ctx context.Context, req *pb.DeleteBlobRequest) (*pb.DeleteBlobResponse, error) {
	uid, err := userID(ctx)
	if err != nil {
		return nil, err
	}
	blobID, err := parseID(req.GetBlobId(), "blob id")
	if err != nil {
		return nil, err
	}
	if err := h.vault.DeleteBlob(ctx, uid, blobID); err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.DeleteBlobResponse{}, nil
}

// Pull implements pb.SyncServiceServer.
func (h *SyncHandler) Pull(ctx context.Context, req *pb.PullRequest) (*pb.PullResponse, error) {
	uid, err := userID(ctx)
	if err != nil {
		return nil, err
	}
	rs, rev, err := h.sync.Pull(ctx, uid, req.GetSince())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &pb.PullResponse{Records: protoconv.RecordsToProto(rs), Revision: rev}, nil
}

// Push implements pb.SyncServiceServer.
func (h *SyncHandler) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	uid, err := userID(ctx)
	if err != nil {
		return nil, err
	}
	changes := make([]model.Change, 0, len(req.GetChanges()))
	for _, c := range req.GetChanges() {
		id, err := uuid.Parse(c.GetId())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid record id")
		}
		changes = append(changes, model.Change{
			ID:          id,
			Type:        protoconv.TypeFromProto(c.GetType()),
			Payload:     c.GetPayload(),
			Deleted:     c.GetDeleted(),
			BaseVersion: c.GetBaseVersion(),
		})
	}
	res, err := h.sync.Push(ctx, uid, changes)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &pb.PushResponse{Conflicts: protoconv.RecordsToProto(res.Conflicts), Revision: res.Revision}
	for _, a := range res.Accepted {
		resp.Accepted = append(resp.Accepted, &pb.Accepted{Id: a.ID.String(), Version: a.Version, Revision: a.Revision})
	}
	return resp, nil
}
