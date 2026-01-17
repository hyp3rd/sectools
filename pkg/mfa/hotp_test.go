package mfa

import (
	"errors"
	"strings"
	"testing"
)

const (
	hotpTestIssuer  = "sectools"
	hotpTestAccount = "user@example.com"
	hotpTestSecret  = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // cspell:disable-line
)

func TestHOTPGenerateAndVerify(t *testing.T) {
	t.Parallel()

	helper, err := NewHOTP(hotpTestSecret)
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	counter := uint64(1)

	code, err := helper.Generate(counter)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, next, err := helper.Verify(code, counter)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid code")
	}

	if next != counter+1 {
		t.Fatalf("expected next counter %d, got %d", counter+1, next)
	}
}

func TestHOTPVerifyWindow(t *testing.T) {
	t.Parallel()

	helper, err := NewHOTP(hotpTestSecret, WithHOTPWindow(1))
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	counter := uint64(5)

	code, err := helper.Generate(counter + 1)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, next, err := helper.Verify(code, counter)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid code within window")
	}

	if next != counter+2 {
		t.Fatalf("expected next counter %d, got %d", counter+2, next)
	}
}

func TestHOTPResync(t *testing.T) {
	t.Parallel()

	helper, err := NewHOTP(hotpTestSecret, WithHOTPResyncWindow(3))
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	counter := uint64(5)

	code1, err := helper.Generate(counter + 2)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	code2, err := helper.Generate(counter + 3)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, next, err := helper.Resync(code1, code2, counter)
	if err != nil {
		t.Fatalf("expected resync, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid resync")
	}

	if next != counter+4 {
		t.Fatalf("expected next counter %d, got %d", counter+4, next)
	}
}

func TestHOTPResyncRejectsNonConsecutive(t *testing.T) {
	t.Parallel()

	helper, err := NewHOTP(hotpTestSecret, WithHOTPResyncWindow(3))
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	counter := uint64(5)

	code1, err := helper.Generate(counter + 1)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	code2, err := helper.Generate(counter + 3)
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, _, err := helper.Resync(code1, code2, counter)
	if err != nil {
		t.Fatalf("expected resync, got %v", err)
	}

	if ok {
		t.Fatalf("expected resync to fail")
	}
}

func TestHOTPInvalidCode(t *testing.T) {
	t.Parallel()

	helper, err := NewHOTP(hotpTestSecret)
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	_, _, err = helper.Verify("invalid", 0)
	if !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}

func TestHOTPSecretTooShort(t *testing.T) {
	t.Parallel()

	_, err := NewHOTP("AAAA")
	if !errors.Is(err, ErrMFASecretTooShort) {
		t.Fatalf("expected ErrMFASecretTooShort, got %v", err)
	}
}

func TestHOTPInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []HOTPOption
	}{
		{
			name: "invalid-digits",
			opts: []HOTPOption{WithHOTPDigits(Digits(99))},
		},
		{
			name: "invalid-algorithm",
			opts: []HOTPOption{WithHOTPAlgorithm(Algorithm(99))},
		},
		{
			name: "invalid-resync-window",
			opts: []HOTPOption{WithHOTPResyncWindow(hotpMaxResyncWindow + 1)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewHOTP(hotpTestSecret, tt.opts...)
			if !errors.Is(err, ErrInvalidMFAConfig) {
				t.Fatalf("expected ErrInvalidMFAConfig, got %v", err)
			}
		})
	}
}

func TestGenerateHOTPKey(t *testing.T) {
	t.Parallel()

	key, err := GenerateHOTPKey(
		WithHOTPKeyIssuer(hotpTestIssuer),
		WithHOTPKeyAccountName(hotpTestAccount),
	)
	if err != nil {
		t.Fatalf("expected key, got %v", err)
	}

	if key.Secret() == "" {
		t.Fatalf("expected secret")
	}

	if !strings.HasPrefix(key.URL(), "otpauth://hotp/") {
		t.Fatalf("expected otpauth url, got %s", key.URL())
	}
}
