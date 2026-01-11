package tokens

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestTokenGenerateAndValidateBase64(t *testing.T) {
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
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("token with space")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestTokenValidateEmpty(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("")
	if !errors.Is(err, ErrTokenEmpty) {
		t.Fatalf("expected ErrTokenEmpty, got %v", err)
	}

	_, err = validator.Validate("   ")
	if !errors.Is(err, ErrTokenEmpty) {
		t.Fatalf("expected ErrTokenEmpty for whitespace-only token, got %v", err)
	}
}

func TestTokenValidateInvalidBase64(t *testing.T) {
	validator, err := NewValidator(WithTokenEncoding(TokenEncodingBase64URL))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("!!!invalid-base64!!!")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for invalid base64, got %v", err)
	}

	_, err = validator.Validate("====")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for invalid base64 padding, got %v", err)
	}
}

func TestTokenValidateInvalidHex(t *testing.T) {
	validator, err := NewValidator(WithTokenEncoding(TokenEncodingHex))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate("gggg")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for invalid hex characters, got %v", err)
	}

	_, err = validator.Validate("abc")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for odd-length hex string, got %v", err)
	}
}

func TestGenerateBytes(t *testing.T) {
	generator, err := NewGenerator()
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	bytes, err := generator.GenerateBytes()
	if err != nil {
		t.Fatalf("expected bytes, got %v", err)
	}

	if len(bytes) < 16 {
		t.Fatalf("expected at least 16 bytes, got %d", len(bytes))
	}
}

func TestGenerateBytesWithMinBytes(t *testing.T) {
	generator, err := NewGenerator(WithTokenMinBytes(32))
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	bytes, err := generator.GenerateBytes()
	if err != nil {
		t.Fatalf("expected bytes, got %v", err)
	}

	if len(bytes) < 32 {
		t.Fatalf("expected at least 32 bytes, got %d", len(bytes))
	}
}

func TestInvalidConfigNegativeMinEntropyBits(t *testing.T) {
	_, err := NewGenerator(WithTokenMinEntropyBits(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative minEntropyBits, got %v", err)
	}

	_, err = NewValidator(WithTokenMinEntropyBits(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative minEntropyBits, got %v", err)
	}
}

func TestInvalidConfigZeroMinEntropyBits(t *testing.T) {
	_, err := NewGenerator(WithTokenMinEntropyBits(0))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for zero minEntropyBits, got %v", err)
	}
}

func TestInvalidConfigNegativeMinBytes(t *testing.T) {
	_, err := NewGenerator(WithTokenMinBytes(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative minBytes, got %v", err)
	}

	_, err = NewValidator(WithTokenMinBytes(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative minBytes, got %v", err)
	}
}

func TestInvalidConfigZeroMinBytes(t *testing.T) {
	_, err := NewGenerator(WithTokenMinBytes(0))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for zero minBytes, got %v", err)
	}
}

func TestInvalidConfigNegativeMaxLength(t *testing.T) {
	_, err := NewGenerator(WithTokenMaxLength(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative maxLength, got %v", err)
	}

	_, err = NewValidator(WithTokenMaxLength(-1))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for negative maxLength, got %v", err)
	}
}

func TestInvalidConfigZeroMaxLength(t *testing.T) {
	_, err := NewGenerator(WithTokenMaxLength(0))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for zero maxLength, got %v", err)
	}
}

func TestTokenRandomness(t *testing.T) {
	generator, err := NewGenerator()
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	token1, err := generator.Generate()
	if err != nil {
		t.Fatalf("expected token1, got %v", err)
	}

	token2, err := generator.Generate()
	if err != nil {
		t.Fatalf("expected token2, got %v", err)
	}

	if token1 == token2 {
		t.Fatalf("expected different tokens, got identical: %s", token1)
	}
}

func TestTokenBytesRandomness(t *testing.T) {
	generator, err := NewGenerator()
	if err != nil {
		t.Fatalf("expected generator, got %v", err)
	}

	bytes1, err := generator.GenerateBytes()
	if err != nil {
		t.Fatalf("expected bytes1, got %v", err)
	}

	bytes2, err := generator.GenerateBytes()
	if err != nil {
		t.Fatalf("expected bytes2, got %v", err)
	}

	if base64.RawURLEncoding.EncodeToString(bytes1) == base64.RawURLEncoding.EncodeToString(bytes2) {
		t.Fatalf("expected different byte sequences, got identical")
	}
}

func TestInvalidEncodingValue(t *testing.T) {
	// TokenEncoding is an int type, so we can pass an invalid value
	invalidEncoding := TokenEncoding(999)

	_, err := NewGenerator(WithTokenEncoding(invalidEncoding))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for invalid encoding value, got %v", err)
	}

	_, err = NewValidator(WithTokenEncoding(invalidEncoding))
	if !errors.Is(err, ErrInvalidTokenConfig) {
		t.Fatalf("expected ErrInvalidTokenConfig for invalid encoding value, got %v", err)
	}
}
