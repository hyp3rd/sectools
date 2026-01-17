package mfa

import (
	"errors"
	"testing"
	"time"
)

type testRateLimiter struct {
	allow bool
	err   error
	calls int
}

func (t *testRateLimiter) Allow() (bool, error) {
	t.calls++
	return t.allow, t.err
}

func TestTOTPVerifyRateLimited(t *testing.T) {
	limiter := &testRateLimiter{}

	helper, err := NewTOTP(totpTestSecret, WithTOTPRateLimiter(limiter))
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	_, err = helper.Verify("123456")
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("expected ErrMFARateLimited, got %v", err)
	}
	if limiter.calls != 1 {
		t.Fatalf("expected limiter to be called")
	}
}

func TestHOTPVerifyRateLimited(t *testing.T) {
	limiter := &testRateLimiter{}

	helper, err := NewHOTP(hotpTestSecret, WithHOTPRateLimiter(limiter))
	if err != nil {
		t.Fatalf("expected hotp helper, got %v", err)
	}

	_, _, err = helper.Verify("123456", 0)
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("expected ErrMFARateLimited, got %v", err)
	}
	if limiter.calls != 1 {
		t.Fatalf("expected limiter to be called")
	}
}

func TestBackupVerifyRateLimited(t *testing.T) {
	limiter := &testRateLimiter{}

	manager, err := NewBackupCodeManager(WithBackupRateLimiter(limiter))
	if err != nil {
		t.Fatalf("expected manager, got %v", err)
	}

	_, _, err = manager.Verify("ABCD", nil)
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("expected ErrMFARateLimited, got %v", err)
	}
	if limiter.calls != 1 {
		t.Fatalf("expected limiter to be called")
	}
}

func TestRateLimiterErrorWraps(t *testing.T) {
	limiter := &testRateLimiter{allow: false, err: errors.New("backend")}

	helper, err := NewTOTP(
		totpTestSecret,
		WithTOTPRateLimiter(limiter),
		WithTOTPClock(func() time.Time { return time.Now() }),
	)
	if err != nil {
		t.Fatalf("expected totp helper, got %v", err)
	}

	_, err = helper.Verify("123456")
	if err == nil || !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("expected ErrMFARateLimited, got %v", err)
	}
}
