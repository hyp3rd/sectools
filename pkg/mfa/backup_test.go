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

func TestBackupCodeInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []BackupOption
		err  error
	}{
		{
			name: "count-too-low",
			opts: []BackupOption{WithBackupCodeCount(0)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "count-too-high",
			opts: []BackupOption{WithBackupCodeCount(backupMaxCount + 1)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "length-too-short",
			opts: []BackupOption{WithBackupCodeLength(backupMinLength - 1)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "length-too-long",
			opts: []BackupOption{WithBackupCodeLength(backupMaxLength + 1)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "group-size-negative",
			opts: []BackupOption{WithBackupCodeGroupSize(-1)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "group-size-too-large",
			opts: []BackupOption{
				WithBackupCodeLength(backupMinLength),
				WithBackupCodeGroupSize(backupMinLength + 1),
			},
			err: ErrInvalidMFAConfig,
		},
		{
			name: "alphabet-duplicate",
			opts: []BackupOption{WithBackupCodeAlphabet("AABCDEFGHJKLMNPQRSTUVWXYZ23456789")}, // cspell:disable-line
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "alphabet-invalid-char",
			opts: []BackupOption{WithBackupCodeAlphabet("ABCDEFGHJKLMNPQRSTUVWXYZ23456789$")}, // cspell:disable-line
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "hasher-conflict",
			opts: []BackupOption{
				WithBackupHasherBcrypt(password.BcryptInteractiveCost),
				WithBackupHasherArgon2id(password.Argon2idBalanced()),
			},
			err: ErrMFAConflictingOptions,
		},
		{
			name: "nil-rate-limiter",
			opts: []BackupOption{WithBackupRateLimiter(nil)},
			err:  ErrInvalidMFAConfig,
		},
		{
			name: "nil-reader",
			opts: []BackupOption{WithBackupCodeReader(nil)},
			err:  ErrInvalidMFAConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBackupCodeManager(tt.opts...)
			if !errors.Is(err, tt.err) {
				t.Fatalf("expected %v, got %v", tt.err, err)
			}
		})
	}
}
