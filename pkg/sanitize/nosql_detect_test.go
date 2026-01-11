package sanitize

import "testing"

func TestNoSQLInjectionDetectorDefault(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.Detect(`{"username":{"$ne":null}}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect(`{"$where":"sleep(1)"}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect("price$usd")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNoSQLInjectionDetectorCustomOperators(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector(WithNoSQLDetectOperators("custom"))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.Detect(`{"$custom":true}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}
}
