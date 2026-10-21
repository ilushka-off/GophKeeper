// Package remote is the client side of the GophKeeper gRPC protocol. It attaches the
// access token to calls, refreshes it shortly before expiry or after an Unauthenticated
// error, and converts protobuf messages to domain types.
package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/protoconv"
)

// ErrNotLoggedIn is returned when there is no valid session; the user has to log in again.
var ErrNotLoggedIn = errors.New("not logged in or session expired: run login")

// ErrUnavailable is returned when the server cannot be reached.
var ErrUnavailable = errors.New("server is unavailable")

// refreshMargin is how long before expiry the access token is refreshed proactively.
const refreshMargin = 30 * time.Second

// TokenStore keeps the session tokens between calls.
type TokenStore interface {
	// Tokens returns the current tokens or ErrNotLoggedIn.
	Tokens(ctx context.Context) (model.Tokens, error)
	// SetTokens replaces the stored tokens.
	SetTokens(ctx context.Context, t model.Tokens) error
}

// Client talks to the GophKeeper server.
type Client struct {
	conn   *grpc.ClientConn
	auth   pb.AuthServiceClient
	vault  pb.VaultServiceClient
	sync   pb.SyncServiceClient
	tokens TokenStore
	now    func() time.Time
}

// TLSCredentials returns transport credentials that trust the CA in caFile,
// or the system roots when caFile is empty.
func TLSCredentials(caFile string) (credentials.TransportCredentials, error) {
	if caFile == "" {
		return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), nil
	}
	creds, err := credentials.NewClientTLSFromFile(caFile, "")
	if err != nil {
		return nil, fmt.Errorf("load CA certificate: %w", err)
	}
	return creds, nil
}

// Dial creates a client for addr. The connection is established lazily on the first call.
func Dial(addr string, creds credentials.TransportCredentials, opts ...grpc.DialOption) (*Client, error) {
	opts = append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, opts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	return New(conn), nil
}

// New creates a client on an existing connection.
func New(conn *grpc.ClientConn) *Client {
	return &Client{
		conn:  conn,
		auth:  pb.NewAuthServiceClient(conn),
		vault: pb.NewVaultServiceClient(conn),
		sync:  pb.NewSyncServiceClient(conn),
		now:   time.Now,
	}
}

// SetTokenStore sets where the client reads and writes session tokens.
func (c *Client) SetTokenStore(ts TokenStore) {
	c.tokens = ts
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// mapErr converts gRPC errors to client errors with readable messages.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	case codes.Unauthenticated:
		return fmt.Errorf("%w: %s", model.ErrUnauthenticated, st.Message())
	case codes.NotFound:
		return model.ErrNotFound
	case codes.AlreadyExists:
		return fmt.Errorf("%w: %s", model.ErrAlreadyExists, st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("%w: %s", model.ErrInvalidArgument, st.Message())
	case codes.PermissionDenied:
		return fmt.Errorf("%w: %s", model.ErrPermissionDenied, st.Message())
	}
	return fmt.Errorf("server error: %s: %s", st.Code(), st.Message())
}

// Register creates an account.
func (c *Client) Register(ctx context.Context, login, password string, salt []byte) (model.Tokens, error) {
	resp, err := c.auth.Register(ctx, &pb.RegisterRequest{Login: login, Password: password, KdfSalt: salt})
	if err != nil {
		return model.Tokens{}, mapErr(err)
	}
	return protoconv.TokensFromProto(resp.GetTokens()), nil
}

// GetSalt returns the KDF salt for login.
func (c *Client) GetSalt(ctx context.Context, login string) ([]byte, error) {
	resp, err := c.auth.GetSalt(ctx, &pb.GetSaltRequest{Login: login})
	if err != nil {
		return nil, mapErr(err)
	}
	return resp.GetKdfSalt(), nil
}

// Login authenticates and returns tokens and the KDF salt.
func (c *Client) Login(ctx context.Context, login, password string) (model.Tokens, []byte, error) {
	resp, err := c.auth.Login(ctx, &pb.LoginRequest{Login: login, Password: password})
	if err != nil {
		return model.Tokens{}, nil, mapErr(err)
	}
	return protoconv.TokensFromProto(resp.GetTokens()), resp.GetKdfSalt(), nil
}

// Logout revokes the refresh token.
func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	_, err := c.auth.Logout(ctx, &pb.LogoutRequest{RefreshToken: refreshToken})
	return mapErr(err)
}

func (c *Client) refresh(ctx context.Context, t model.Tokens) (model.Tokens, error) {
	resp, err := c.auth.Refresh(ctx, &pb.RefreshRequest{RefreshToken: t.RefreshToken})
	if status.Code(err) == codes.Unauthenticated {
		return model.Tokens{}, ErrNotLoggedIn
	}
	if err != nil {
		return model.Tokens{}, mapErr(err)
	}
	nt := protoconv.TokensFromProto(resp.GetTokens())
	if err := c.tokens.SetTokens(ctx, nt); err != nil {
		return model.Tokens{}, err
	}
	return nt, nil
}

// authCtx returns ctx with a valid access token, refreshing it if it is about to expire.
func (c *Client) authCtx(ctx context.Context, forceRefresh bool) (context.Context, error) {
	if c.tokens == nil {
		return nil, ErrNotLoggedIn
	}
	t, err := c.tokens.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	if forceRefresh || c.now().Add(refreshMargin).After(t.AccessExpiresAt) {
		if t, err = c.refresh(ctx, t); err != nil {
			return nil, err
		}
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+t.AccessToken), nil
}

// call runs an authenticated call and retries it once with a fresh token on Unauthenticated.
func (c *Client) call(ctx context.Context, fn func(ctx context.Context) error) error {
	actx, err := c.authCtx(ctx, false)
	if err != nil {
		return err
	}
	err = fn(actx)
	if status.Code(err) != codes.Unauthenticated {
		return mapErr(err)
	}
	if actx, err = c.authCtx(ctx, true); err != nil {
		return err
	}
	return mapErr(fn(actx))
}

// GetRecord returns a record from the server.
func (c *Client) GetRecord(ctx context.Context, id uuid.UUID) (model.Record, error) {
	var rec model.Record
	err := c.call(ctx, func(ctx context.Context) error {
		resp, err := c.vault.GetRecord(ctx, &pb.GetRecordRequest{Id: id.String()})
		if err != nil {
			return err
		}
		rec, err = protoconv.RecordFromProto(resp.GetRecord())
		return err
	})
	return rec, err
}

// Pull returns changes after revision since and the current revision.
func (c *Client) Pull(ctx context.Context, since int64) ([]model.Record, int64, error) {
	var (
		recs []model.Record
		rev  int64
	)
	err := c.call(ctx, func(ctx context.Context) error {
		resp, err := c.sync.Pull(ctx, &pb.PullRequest{Since: since})
		if err != nil {
			return err
		}
		recs = recs[:0]
		for _, r := range resp.GetRecords() {
			rec, err := protoconv.RecordFromProto(r)
			if err != nil {
				return err
			}
			recs = append(recs, rec)
		}
		rev = resp.GetRevision()
		return nil
	})
	return recs, rev, err
}

// Push sends local changes.
func (c *Client) Push(ctx context.Context, changes []model.Change) (model.PushResult, error) {
	req := &pb.PushRequest{}
	for _, ch := range changes {
		req.Changes = append(req.Changes, &pb.Change{
			Id:          ch.ID.String(),
			Type:        protoconv.TypeToProto(ch.Type),
			Payload:     ch.Payload,
			Deleted:     ch.Deleted,
			BaseVersion: ch.BaseVersion,
		})
	}
	var res model.PushResult
	err := c.call(ctx, func(ctx context.Context) error {
		resp, err := c.sync.Push(ctx, req)
		if err != nil {
			return err
		}
		res = model.PushResult{Revision: resp.GetRevision()}
		for _, a := range resp.GetAccepted() {
			id, err := uuid.Parse(a.GetId())
			if err != nil {
				return fmt.Errorf("bad accepted id: %w", err)
			}
			res.Accepted = append(res.Accepted, model.Accepted{ID: id, Version: a.GetVersion(), Revision: a.GetRevision()})
		}
		for _, r := range resp.GetConflicts() {
			rec, err := protoconv.RecordFromProto(r)
			if err != nil {
				return err
			}
			res.Conflicts = append(res.Conflicts, rec)
		}
		return nil
	})
	return res, err
}

// UploadBlob streams chunks produced by produce to the server.
// produce calls send for every chunk in order.
func (c *Client) UploadBlob(ctx context.Context, blobID uuid.UUID, produce func(send func([]byte) error) error) (int64, error) {
	actx, err := c.authCtx(ctx, false)
	if err != nil {
		return 0, err
	}
	stream, err := c.vault.UploadBlob(actx)
	if err != nil {
		return 0, mapErr(err)
	}
	if err := stream.Send(&pb.UploadBlobRequest{Data: &pb.UploadBlobRequest_BlobId{BlobId: blobID.String()}}); err != nil {
		return 0, c.streamErr(stream, err)
	}
	err = produce(func(chunk []byte) error {
		if err := stream.Send(&pb.UploadBlobRequest{Data: &pb.UploadBlobRequest_Chunk{Chunk: chunk}}); err != nil {
			return c.streamErr(stream, err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, mapErr(err)
	}
	return resp.GetSize(), nil
}

// streamErr returns the real server error after Send failed with io.EOF.
func (c *Client) streamErr(stream grpc.ClientStreamingClient[pb.UploadBlobRequest, pb.UploadBlobResponse], err error) error {
	if errors.Is(err, io.EOF) {
		_, err = stream.CloseAndRecv()
	}
	return mapErr(err)
}

// DownloadBlob calls fn for every chunk of the blob.
func (c *Client) DownloadBlob(ctx context.Context, blobID uuid.UUID, fn func([]byte) error) error {
	actx, err := c.authCtx(ctx, false)
	if err != nil {
		return err
	}
	stream, err := c.vault.DownloadBlob(actx, &pb.DownloadBlobRequest{BlobId: blobID.String()})
	if err != nil {
		return mapErr(err)
	}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return mapErr(err)
		}
		if err := fn(msg.GetChunk()); err != nil {
			return err
		}
	}
}

// DeleteBlob removes a blob from the server.
func (c *Client) DeleteBlob(ctx context.Context, blobID uuid.UUID) error {
	return c.call(ctx, func(ctx context.Context) error {
		_, err := c.vault.DeleteBlob(ctx, &pb.DeleteBlobRequest{BlobId: blobID.String()})
		return err
	})
}
