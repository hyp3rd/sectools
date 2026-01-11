package tokens

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidTokenConfig indicates an invalid token configuration.
	ErrInvalidTokenConfig = ewrap.New("invalid token config")
	// ErrTokenEmpty indicates the token is empty.
	ErrTokenEmpty = ewrap.New("token is empty")
	// ErrTokenTooLong indicates the token exceeds the configured max length.
	ErrTokenTooLong = ewrap.New("token is too long")
	// ErrTokenTooShort indicates the token is shorter than the minimum bytes.
	ErrTokenTooShort = ewrap.New("token is too short")
	// ErrTokenInvalid indicates the token is malformed or has invalid encoding.
	ErrTokenInvalid = ewrap.New("token is invalid")
	// ErrTokenInsufficientEntropy indicates the token lacks required entropy.
	ErrTokenInsufficientEntropy = ewrap.New("token entropy is insufficient")
)
