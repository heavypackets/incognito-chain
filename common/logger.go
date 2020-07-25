package common

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type contextIDType int

const (
	requestIDKey contextIDType = iota
)

// WithRequestID adds a random requestID to a context
// If the given identifer already has a UUID, we use it as the requestID
// If not, we generate one, use it and also set the value back to the identifier
func WithRequestID(ctx context.Context, iden Identifier) context.Context {
	id := iden.GetUUID()
	if len(id) == 0 {
		randUUID, _ := uuid.NewRandom()
		id = randUUID.String()
		iden.SetUUID(id)
	}
	return context.WithValue(ctx, requestIDKey, id)
}

// Logger returns a logger attached with a requestID if it's
// available in the context
func NewLogger(ctx context.Context, logger *zap.SugaredLogger) *zap.SugaredLogger {
	l := logger
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		l = l.With("requestID", requestID)
	}
	return l
}

type Identifier interface {
	GetUUID() string
	SetUUID(uuid string)
}
