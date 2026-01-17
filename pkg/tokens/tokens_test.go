package tokens

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestTokenGenerateAndValidateBase64(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator()
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	token, err := generator.Generate()
	if err != nil {
		t.Fatalf("expected token, got %v", err)
	}

	decoded, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("expected token valid, got %v", err)
	}

	if len(decoded) < 16 {
		t.Fatalf("expected at least 16 bytes, got %d", len(decoded))
	}
}

func TestTokenGenerateHex(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator(WithTokenEncoding(TokenEncodingHex))
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	validator, err := NewValidator(WithTokenEncoding(TokenEncodingHex))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	token, err := generator.Generate()
	if err != nil {
		t.Fatalf("expected token, got %v", err)
	}

	decoded, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("expected token valid, got %v", err)
	}

	if len(decoded) < 16 {
		t.Fatalf("expected at least 16 bytes, got %d", len(decoded))
	}
}

func TestTokenValidateMaxLength(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(
		WithTokenMaxLength(4),
		WithTokenMinEntropyBits(8),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("aaaaa")
	if !errors.Is(err, ErrTokenTooLong) {
		t.Fatalf("expected ErrTokenTooLong, got %v", err)
	}
}

func TestTokenValidateInsufficientEntropy(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(WithTokenMinEntropyBits(128))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	// Note: make([]byte, 8) produces an all-zero token. This test exercises the
	// length-based entropy check (8 bytes = 64 bits) rather than measuring actual
	// randomness of the token bytes.
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 8))

	_, err = validator.Validate(short)
	if !errors.Is(err, ErrTokenInsufficientEntropy) {
		t.Fatalf("expected ErrTokenInsufficientEntropy, got %v", err)
	}
}

func TestTokenValidateMinBytes(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(WithTokenMinBytes(32))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))

	_, err = validator.Validate(short)
	if !errors.Is(err, ErrTokenTooShort) {
		t.Fatalf("expected ErrTokenTooShort, got %v", err)
	}
}

func TestTokenValidateWhitespace(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("token with space")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}
