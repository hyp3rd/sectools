package password

import (
	"errors"
	"testing"
)

const (
	keyLength = 32
)

func TestArgon2idHashVerify(t *testing.T) {
	t.Parallel()
	//nolint:revive
	params := Argon2idParams{
		Memory:     8 * 1024,
		Time:       1,
		Threads:    1,
		SaltLength: 16,
		KeyLength:  keyLength,
	}

	hasher, err := NewArgon2id(params)
	if err != nil {
		t.Fatalf("expected hasher, got error: %v", err)
	}

	hash, err := hasher.Hash([]byte("password"))
	if err != nil {
		t.Fatalf("expected hash, got error: %v", err)
	}

	ok, needsRehash, err := hasher.Verify([]byte("password"), hash)
	if err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}

	if !ok {
		t.Fatal("expected password match")
	}

	if needsRehash {
		t.Fatal("expected no rehash with same params")
	}

	stronger, err := NewArgon2id(Argon2idParams{
		Memory:     16 * 1024,
		Time:       2,
		Threads:    1,
		SaltLength: 16,
		KeyLength:  keyLength,
	})
	if err != nil {
		t.Fatalf("expected stronger hasher, got error: %v", err)
	}

	ok, needsRehash, err = stronger.Verify([]byte("password"), hash)
	if err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}

	if !ok {
		t.Fatal("expected password match")
	}

	if !needsRehash {
		t.Fatal("expected rehash for stronger params")
	}
}

func TestArgon2idInvalidHash(t *testing.T) {
	t.Parallel()

	hasher, err := NewArgon2id(Argon2idParams{
		Memory:     8 * 1024,
		Time:       1,
		Threads:    1,
		SaltLength: 16,
		KeyLength:  keyLength,
	})
	if err != nil {
		t.Fatalf("expected hasher, got error: %v", err)
	}

	_, _, err = hasher.Verify([]byte("password"), "invalid")
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}
}
