package grpcapi

import (
	"context"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
)

type ctxKey int

const (
	userIDKey ctxKey = iota
	loggerKey
)

// WithUserID returns a context carrying the authenticated user id.
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserIDFromContext returns the authenticated user id put into the context by the auth interceptor.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func userID(ctx context.Context) (uuid.UUID, error) {
	id, ok := UserIDFromContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return id, nil
}

func loggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// Authenticator verifies access tokens.
type Authenticator interface {
	Authenticate(accessToken string) (uuid.UUID, error)
}

// publicMethods do not require an access token.
var publicMethods = map[string]bool{
	pb.AuthService_Register_FullMethodName: true,
	pb.AuthService_GetSalt_FullMethodName:  true,
	pb.AuthService_Login_FullMethodName:    true,
	pb.AuthService_Refresh_FullMethodName:  true,
	pb.AuthService_Logout_FullMethodName:   true,
}

func authenticate(ctx context.Context, auth Authenticator, method string) (context.Context, error) {
	if publicMethods[method] {
		return ctx, nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing access token")
	}
	raw, ok := strings.CutPrefix(values[0], "Bearer ")
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authorization must be a Bearer token")
	}
	id, err := auth.Authenticate(raw)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
	}
	return WithUserID(ctx, id), nil
}

// AuthUnaryInterceptor checks the Bearer access token of every call except the public
// AuthService methods and puts the user id into the context.
func AuthUnaryInterceptor(auth Authenticator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := authenticate(ctx, auth, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// AuthStreamInterceptor is the streaming counterpart of AuthUnaryInterceptor.
func AuthStreamInterceptor(auth Authenticator) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authenticate(ss.Context(), auth, info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// LoggingUnaryInterceptor logs every call with its duration and status code
// and makes the logger available to handlers.
func LoggingUnaryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		ctx = context.WithValue(ctx, loggerKey, log.With("method", info.FullMethod))
		resp, err := handler(ctx, req)
		logCall(ctx, start, err)
		return resp, err
	}
}

// LoggingStreamInterceptor is the streaming counterpart of LoggingUnaryInterceptor.
func LoggingStreamInterceptor(log *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		ctx := context.WithValue(ss.Context(), loggerKey, log.With("method", info.FullMethod))
		err := handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
		logCall(ctx, start, err)
		return err
	}
}

func logCall(ctx context.Context, start time.Time, err error) {
	code := status.Code(err)
	level := slog.LevelInfo
	if code == codes.Internal || code == codes.Unknown {
		level = slog.LevelError
	}
	loggerFrom(ctx).Log(ctx, level, "grpc call",
		"code", code.String(),
		"duration", time.Since(start),
	)
}

// RecoveryUnaryInterceptor turns a panic in a handler into an Internal error.
func RecoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				loggerFrom(ctx).ErrorContext(ctx, "panic", "panic", r, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor turns a panic in a stream handler into an Internal error.
func RecoveryStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				loggerFrom(ss.Context()).Error("panic", "panic", r, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}
