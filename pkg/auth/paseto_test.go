package auth

import (
	"errors"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
)

func TestPasetoLocalRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	key := paseto.NewV4SymmetricKey()

	local, err := NewPasetoLocal(
		WithPasetoLocalKey(key),
		WithPasetoLocalIssuer("sectools"),
		WithPasetoLocalAudience("apps"),
		WithPasetoLocalSubject("user-1"),
		WithPasetoLocalClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("expected local helper, got error: %v", err)
	}

	token := paseto.NewToken()
	token.SetExpiration(now.Add(time.Hour))
	token.SetIssuer("sectools")
	token.SetAudience("apps")
	token.SetSubject("user-1")
	token.SetString("role", "admin")

	encrypted, err := local.Encrypt(&token)
	if err != nil {
		t.Fatalf("expected encrypted token, got error: %v", err)
	}

	parsed, err := local.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("expected parsed token, got error: %v", err)
	}

	if parsed == nil {
		t.Fatalf("expected parsed token")
	}
}

func TestPasetoPublicRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	secret := paseto.NewV4AsymmetricSecretKey()
	public := secret.Public()

	signer, err := NewPasetoPublicSigner(
		WithPasetoPublicSecretKey(secret),
	)
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	verifier, err := NewPasetoPublicVerifier(
		WithPasetoPublicKey(public),
		WithPasetoPublicIssuer("sectools"),
		WithPasetoPublicAudience("apps"),
		WithPasetoPublicClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("expected verifier, got error: %v", err)
	}

	token := paseto.NewToken()
	token.SetExpiration(now.Add(time.Hour))
	token.SetIssuer("sectools")
	token.SetAudience("apps")
	token.SetString("role", "admin")

	signed, err := signer.Sign(&token)
	if err != nil {
		t.Fatalf("expected signed token, got error: %v", err)
	}

	parsed, err := verifier.Verify(signed)
	if err != nil {
		t.Fatalf("expected parsed token, got error: %v", err)
	}

	if parsed == nil {
		t.Fatalf("expected parsed token")
	}
}

func TestPasetoMissingExpiration(t *testing.T) {
	t.Parallel()

	key := paseto.NewV4SymmetricKey()

	local, err := NewPasetoLocal(WithPasetoLocalKey(key))
	if err != nil {
		t.Fatalf("expected local helper, got error: %v", err)
	}

	missingExp := paseto.NewToken()
	if _, err := local.Encrypt(&missingExp); !errors.Is(err, ErrPasetoMissingExpiry) {
		t.Fatalf("expected ErrPasetoMissingExpiry, got %v", err)
	}

	secret := paseto.NewV4AsymmetricSecretKey()

	signer, err := NewPasetoPublicSigner(WithPasetoPublicSecretKey(secret))
	if err != nil {
		t.Fatalf("expected signer, got error: %v", err)
	}

	if _, err := signer.Sign(&missingExp); !errors.Is(err, ErrPasetoMissingExpiry) {
		t.Fatalf("expected ErrPasetoMissingExpiry, got %v", err)
	}
}
