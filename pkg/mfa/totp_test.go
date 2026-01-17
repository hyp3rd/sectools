package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	totpTestIssuer  = "sectools"
	totpTestAccount = "user@example.com"
	//nolint:gosec
	totpTestSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // cspell:disable-line
)

func TestTOTPGenerateAndVerify(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, time.January, 2, 15, 4, 5, 0, time.UTC)
	clock := func() time.Time {
		return now
	}

	helper, err := NewTOTP(totpTestSecret, WithTOTPClock(clock))
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	code, err := helper.Generate()
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, err := helper.Verify(code)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid code")
	}

	badCode := code[:len(code)-1] + "0"
	if badCode == code {
		badCode = code[:len(code)-1] + "1"
	}

	ok, err = helper.Verify(badCode)
	if err != nil {
		t.Fatalf("expected mismatch without error, got %v", err)
	}

	if ok {
		t.Fatalf("expected invalid code")
	}
}

func TestTOTPVerifySkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, time.January, 2, 15, 4, 5, 0, time.UTC)
	clock := func() time.Time {
		return now
	}

	helper, err := NewTOTP(totpTestSecret, WithTOTPClock(clock), WithTOTPAllowedSkew(1))
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	code, err := helper.Generate()
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	now = now.Add(totpDefaultPeriod)

	ok, err := helper.Verify(code)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid code within skew")
	}
}

func TestTOTPVerifyWithStep(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, time.January, 2, 15, 4, 5, 0, time.UTC)
	clock := func() time.Time {
		return now
	}

	helper, err := NewTOTP(totpTestSecret, WithTOTPClock(clock))
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	code, err := helper.Generate()
	if err != nil {
		t.Fatalf("expected code, got %v", err)
	}

	ok, step, err := helper.VerifyWithStep(code)
	if err != nil {
		t.Fatalf("expected verify, got %v", err)
	}

	if !ok {
		t.Fatalf("expected valid code")
	}

	expectedStep := uint64(now.Unix() / int64(totpDefaultPeriod/time.Second))
	if step != expectedStep {
		t.Fatalf("expected step %d, got %d", expectedStep, step)
	}
}

func TestTOTPInvalidCode(t *testing.T) {
	t.Parallel()

	helper, err := NewTOTP(totpTestSecret)
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	_, err = helper.Verify("invalid")
	if !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("expected ErrMFAInvalidCode, got %v", err)
	}
}

func TestTOTPSecretTooShort(t *testing.T) {
	t.Parallel()

	_, err := NewTOTP("AAAA")
	if !errors.Is(err, ErrMFASecretTooShort) {
		t.Fatalf("expected ErrMFASecretTooShort, got %v", err)
	}
}

func TestTOTPInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []TOTPOption
	}{
		{
			name: "invalid-digits",
			opts: []TOTPOption{WithTOTPDigits(Digits(99))},
		},
		{
			name: "invalid-algorithm",
			opts: []TOTPOption{WithTOTPAlgorithm(Algorithm(99))},
		},
		{
			name: "period-too-short",
			opts: []TOTPOption{WithTOTPPeriod(totpMinPeriod - time.Second)},
		},
		{
			name: "period-not-second-aligned",
			opts: []TOTPOption{WithTOTPPeriod(totpMinPeriod + time.Millisecond)},
		},
		{
			name: "period-too-long",
			opts: []TOTPOption{WithTOTPPeriod(totpMaxPeriod + time.Second)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewTOTP(totpTestSecret, tt.opts...)
			if !errors.Is(err, ErrInvalidMFAConfig) {
				t.Fatalf("expected ErrInvalidMFAConfig, got %v", err)
			}
		})
	}
}

func TestGenerateTOTPKey(t *testing.T) {
	t.Parallel()

	key, err := GenerateTOTPKey(
		WithTOTPKeyIssuer(totpTestIssuer),
		WithTOTPKeyAccountName(totpTestAccount),
	)
	if err != nil {
		t.Fatalf("expected key, got %v", err)
	}

	if key.Secret() == "" {
		t.Fatalf("expected secret")
	}

	if !strings.HasPrefix(key.URL(), "otpauth://totp/") {
		t.Fatalf("expected otpauth url, got %s", key.URL())
	}
}
