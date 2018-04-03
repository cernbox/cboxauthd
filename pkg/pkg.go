package pkg

import (
	"context"
	"fmt"
)

type UserBackendErrorCode string

const (
	UserBackendErrorNotFound           UserBackendErrorCode = "USERBACKEND_ERROR_NOT_FOUND"
	UserBackendErrorInvalidCredentials                      = "USERBACKED_ERROR_INVALID_CREDENTIALS"
)

func NewUserBackendError(code UserBackendErrorCode) UserBackendError {
	return UserBackendError{Code: code}
}

type UserBackendError struct {
	Code    UserBackendErrorCode
	Message string
}

func (sr UserBackendError) WithMessage(msg string) UserBackendError {
	sr.Message = msg
	return sr
}

func (sr UserBackendError) Error() string {
	return fmt.Sprintf("%s: %s", sr.Code, sr.Message)
}

type UserBackend interface {
	Authenticate(ctx context.Context, username, password string) error
	DumpCache(ctx context.Context) (map[string]int64, error)
	SetExpiration(ctx context.Context, key string, expiration int64)
	DeleteCacheEntry(ctx context.Context, key string)
}
