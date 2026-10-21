// Package grpcapi exposes the server services over gRPC: request handlers for
// AuthService, VaultService and SyncService, mapping of domain errors to gRPC codes,
// and interceptors for authentication, logging and panic recovery.
package grpcapi

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ilushka-off/GophKeeper/internal/model"
)

func parseID(s, what string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid %s", what)
	}
	return id, nil
}

// toStatus maps domain errors to gRPC status codes. Unknown errors become Internal
// without leaking details to the client.
func toStatus(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	switch {
	case errors.Is(err, model.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, model.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, model.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, model.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, model.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, "unauthenticated")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	loggerFrom(ctx).ErrorContext(ctx, "internal error", "error", err)
	return status.Error(codes.Internal, "internal error")
}
