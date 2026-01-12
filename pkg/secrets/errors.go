package secrets

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidRedactorConfig indicates an invalid redactor configuration.
	ErrInvalidRedactorConfig = ewrap.New("invalid redactor config")
	// ErrInvalidSecretConfig indicates an invalid secret detector configuration.
	ErrInvalidSecretConfig = ewrap.New("invalid secret detector config")

	// ErrSecretInputTooLong indicates the input exceeds the configured max length.
	ErrSecretInputTooLong = ewrap.New("secret input too long")
	// ErrSecretDetected indicates that a secret was detected in the input.
	ErrSecretDetected = ewrap.New("secret detected")
)
