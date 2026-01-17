package sanitize

import (
	"errors"
	"testing"
)

const (
	errMsgDetector = "expected detector, got %v"
)

func TestNoSQLInjectionDetectorDefault(t *testing.T) {
	t.Parallel()

	detector, err := NewNoSQLInjectionDetector()
	if err != nil {
		t.Fatalf(errMsgDetector, err)
	}

	err = detector.Detect(`{"username":{"$ne":null}}`)
	if !errors.Is(err, ErrNoSQLInjectionDetected) {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect(`{"$where":"sleep(1)"}`)
	if !errors.Is(err, ErrNoSQLInjectionDetected) {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect("price$usd")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNoSQLInjectionDetectorCustomOperators(t *testing.T) {
	t.Parallel()

	detector, err := NewNoSQLInjectionDetector(WithNoSQLDetectOperators("custom"))
	if err != nil {
		t.Fatalf(errMsgDetector, err)
	}

	err = detector.Detect(`{"$custom":true}`)
	if !errors.Is(err, ErrNoSQLInjectionDetected) {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}
}

func TestNoSQLInjectionDetectorMaxLength(t *testing.T) {
	t.Parallel()

	detector, err := NewNoSQLInjectionDetector(WithNoSQLDetectMaxLength(1))
	if err != nil {
		t.Fatalf(errMsgDetector, err)
	}

	err = detector.Detect("ab")
	if !errors.Is(err, ErrNoSQLInputTooLong) {
		t.Fatalf("expected ErrNoSQLInputTooLong, got %v", err)
	}
}
