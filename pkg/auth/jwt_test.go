package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTSignerMissingExpiration(t *testing.T) {
	signer, err := NewJWTSigner(
		WithJWTSigningAlgorithm("HS256"),
		WithJWTSigningKey([]byte("secret")),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	_, err = signer.Sign(jwt.RegisteredClaims{})
	if !errors.Is(err, ErrJWTMissingExpiration) {
		t.Fatalf("expected ErrJWTMissingExpiration, got %v", err)
	}
}

func TestJWTSignVerifyRoundTrip(t *testing.T) {
	now := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	secret := []byte("supersecret")

	signer, err := NewJWTSigner(
		WithJWTSigningAlgorithm("HS256"),
		WithJWTSigningKey(secret),
		WithJWTSigningKeyID("kid-1"),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	verifier, err := NewJWTVerifier(
		WithJWTAllowedAlgorithms("HS256"),
		WithJWTVerificationKey(secret),
		WithJWTIssuer("sectools"),
		WithJWTAudience("apps"),
		WithJWTClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("expected verifier, got error: %v", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "sectools",
		Subject:   "user-123",
		Audience:  jwt.ClaimStrings{"apps"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("expected token, got error: %v", err)
	}

	parsed := &jwt.RegisteredClaims{}
	if err := verifier.Verify(token, parsed); err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}

	if parsed.Subject != "user-123" {
		t.Fatalf("expected subject user-123, got %s", parsed.Subject)
	}
}

func TestJWTVerifierAudienceMismatch(t *testing.T) {
	now := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	secret := []byte("supersecret")

	signer, err := NewJWTSigner(
		WithJWTSigningAlgorithm("HS256"),
		WithJWTSigningKey(secret),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	verifier, err := NewJWTVerifier(
		WithJWTAllowedAlgorithms("HS256"),
		WithJWTVerificationKey(secret),
		WithJWTIssuer("sectools"),
		WithJWTAudience("expected"),
		WithJWTClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("expected verifier, got error: %v", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "sectools",
		Audience:  jwt.ClaimStrings{"different"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("expected token, got error: %v", err)
	}

	parsed := &jwt.RegisteredClaims{}
	if err := verifier.Verify(token, parsed); !errors.Is(err, ErrJWTInvalidAudience) {
		t.Fatalf("expected ErrJWTInvalidAudience, got %v", err)
	}
}

func TestJWTVerifierKeySetRequiresKid(t *testing.T) {
	now := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	secret := []byte("supersecret")

	signerWithKid, err := NewJWTSigner(
		WithJWTSigningAlgorithm("HS256"),
		WithJWTSigningKey(secret),
		WithJWTSigningKeyID("kid-1"),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	signerWithoutKid, err := NewJWTSigner(
		WithJWTSigningAlgorithm("HS256"),
		WithJWTSigningKey(secret),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	verifier, err := NewJWTVerifier(
		WithJWTAllowedAlgorithms("HS256"),
		WithJWTVerificationKeys(map[string]any{"kid-1": secret}),
		WithJWTIssuer("sectools"),
		WithJWTAudience("apps"),
		WithJWTClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("expected verifier, got error: %v", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "sectools",
		Audience:  jwt.ClaimStrings{"apps"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}

	tokenWithKid, err := signerWithKid.Sign(claims)
	if err != nil {
		t.Fatalf("expected token, got error: %v", err)
	}

	if err := verifier.Verify(tokenWithKid, &jwt.RegisteredClaims{}); err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}

	tokenWithoutKid, err := signerWithoutKid.Sign(claims)
	if err != nil {
		t.Fatalf("expected token, got error: %v", err)
	}

	if err := verifier.Verify(tokenWithoutKid, &jwt.RegisteredClaims{}); !errors.Is(err, ErrJWTMissingKeyID) {
		t.Fatalf("expected ErrJWTMissingKeyID, got %v", err)
	}
}
