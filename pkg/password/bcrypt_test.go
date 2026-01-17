package password

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHashVerify(t *testing.T) {
	t.Parallel()

	hasher, err := NewBcrypt(bcrypt.MinCost)
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
		t.Fatalf("expected password match")
	}

	if needsRehash {
		t.Fatalf("expected no rehash with same cost")
	}

	stronger, err := NewBcrypt(bcrypt.MinCost + 1)
	if err != nil {
		t.Fatalf("expected hasher, got error: %v", err)
	}

	ok, needsRehash, err = stronger.Verify([]byte("password"), hash)
	if err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}

	if !ok {
		t.Fatalf("expected password match")
	}

	if !needsRehash {
		t.Fatalf("expected rehash with higher cost")
	}
}

func TestBcryptPasswordTooLong(t *testing.T) {
	t.Parallel()

	hasher, err := NewBcrypt(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("expected hasher, got error: %v", err)
	}

	longPassword := make([]byte, bcryptMaxPasswordLength+1)

	_, err = hasher.Hash(longPassword)
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}
}
