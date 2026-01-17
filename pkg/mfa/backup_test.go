package mfa

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyp3rd/sectools/pkg/password"
)

func TestBackupCodeGenerateAndVerify(t *testing.T) {
	manager, err := NewBackupCodeManager(
		WithBackupCodeCount(3),
		WithBackupHasherBcrypt(password.BcryptInteractiveCost),
	)
	if err != nil {
		t.Fatalf("expected manager, got %v", err)
	}

	set, err := manager.Generate()
	if err != nil {
		t.Fatalf("expected codes, got %v", err)
	}

	if len(set.Codes) != 3 || len(set.Hashes) != 3 {
		t.Fatalf("expected 3 codes and hashes")
	}

	code := set.Codes[0]
	ok, remaining, err := manager.Verify(code, set.Hashes)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}
	if !ok {
		t.Fatalf("expected valid code")
	}
	if len(remaining) != 2 {
		t.Fatalf("expected remaining hashes to shrink")
	}

	ok, _, err = manager.Verify(code, remaining)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}
	if ok {
		t.Fatalf("expected replayed code to fail")
	}
}

func TestBackupCodeVerifyNormalizesInput(t *testing.T) {
	manager, err := NewBackupCodeManager(
		WithBackupCodeCount(1),
		WithBackupHasherBcrypt(password.BcryptInteractiveCost),
	)
	if err != nil {
		t.Fatalf("expected manager, got %v", err)
	}

	set, err := manager.Generate()
	if err != nil {
		t.Fatalf("expected codes, got %v", err)
	}

	code := set.Codes[0]
	normalized := strings.ToLower(strings.ReplaceAll(code, "-", " "))

	ok, remaining, err := manager.Verify(normalized, set.Hashes)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}
	if !ok || len(remaining) != 0 {
		t.Fatalf("expected normalized code to verify")
	}
}

func TestBackupCodeInvalidInput(t *testing.T) {
	manager, err := NewBackupCodeManager()
	if err != nil {
		t.Fatalf("expected manager, got %v", err)
	}

	_, _, err = manager.Verify("invalid", []string{"hash"})
	if !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}

func TestBackupCodeInvalidAlphabet(t *testing.T) {
	_, err := NewBackupCodeManager(WithBackupCodeAlphabet("ABC"))
	if !errors.Is(err, ErrInvalidMFAConfig) {
		t.Fatalf("expected ErrInvalidMFAConfig, got %v", err)
	}
}
