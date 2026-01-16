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
	totpTestSecret  = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // cspell:disable-line
)

func TestTOTPGenerateAndVerify(t *testing.T) {
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

func TestTOTPInvalidCode(t *testing.T) {
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
	_, err := NewTOTP("AAAA")
	if !errors.Is(err, ErrMFASecretTooShort) {
		t.Fatalf("expected ErrMFASecretTooShort, got %v", err)
	}
}

func TestGenerateTOTPKey(t *testing.T) {
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
