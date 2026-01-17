package mfa

import (
	"errors"
	"testing"
	"time"

	"github.com/hyp3rd/ewrap"
)

const (
	errMsgExpectedTOTPHelper        = "expected totp helper, got %v"
	errMsgExpectedErrMFARateLimited = "expected ErrMFARateLimited, got %v"
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
	t.Parallel()

	limiter := &testRateLimiter{}

	helper, err := NewTOTP(totpTestSecret, WithTOTPRateLimiter(limiter))
	if err != nil {
		t.Fatalf(errMsgExpectedTOTPHelper, err)
	}

	_, err = helper.Verify("123456")
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf(errMsgExpectedErrMFARateLimited, err)
	}

	if limiter.calls != 1 {
		t.Fatal("expected limiter to be called")
	}
}

func TestHOTPVerifyRateLimited(t *testing.T) {
	t.Parallel()

	limiter := &testRateLimiter{}

	helper, err := NewHOTP(hotpTestSecret, WithHOTPRateLimiter(limiter))
	if err != nil {
		t.Fatalf(errExpectedHelper, err)
	}

	_, _, err = helper.Verify("123456", 0)
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf(errMsgExpectedErrMFARateLimited, err)
	}

	if limiter.calls != 1 {
		t.Fatal("expected limiter to be called")
	}
}

func TestBackupVerifyRateLimited(t *testing.T) {
	t.Parallel()

	limiter := &testRateLimiter{}

	manager, err := NewBackupCodeManager(WithBackupRateLimiter(limiter))
	if err != nil {
		t.Fatalf("expected manager, got %v", err)
	}

	_, _, err = manager.Verify("ABCD", nil)
	if !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf(errMsgExpectedErrMFARateLimited, err)
	}

	if limiter.calls != 1 {
		t.Fatal("expected limiter to be called")
	}
}

func TestRateLimiterErrorWraps(t *testing.T) {
	t.Parallel()

	limiter := &testRateLimiter{allow: false, err: ewrap.New("backend")}

	helper, err := NewTOTP(
		totpTestSecret,
		WithTOTPRateLimiter(limiter),
		WithTOTPClock(time.Now),
	)
	if err != nil {
		t.Fatalf(errMsgExpectedTOTPHelper, err)
	}

	_, err = helper.Verify("123456")
	if err == nil || !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf(errMsgExpectedErrMFARateLimited, err)
	}
}
