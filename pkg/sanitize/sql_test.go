package sanitize

import (
	"errors"
	"testing"
)

func TestSQLSanitizeIdentifier(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewSQLSanitizer()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize("users")
	if err != nil {
		t.Fatalf("expected sanitized identifier, got %v", err)
	}

	if output != "users" {
		t.Fatalf("expected users, got %q", output)
	}

	_, err = sanitizer.Sanitize("users;drop")
	if !errors.Is(err, ErrSQLIdentifierInvalid) {
		t.Fatalf("expected ErrSQLIdentifierInvalid, got %v", err)
	}
}

func TestSQLSanitizeQualifiedIdentifier(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewSQLSanitizer(WithSQLAllowQualifiedIdentifiers(true))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize("public.users")
	if err != nil {
		t.Fatalf("expected sanitized identifier, got %v", err)
	}

	if output != "public.users" {
		t.Fatalf("expected public.users, got %q", output)
	}

	_, err = sanitizer.Sanitize("public..users")
	if !errors.Is(err, ErrSQLIdentifierInvalid) {
		t.Fatalf("expected ErrSQLIdentifierInvalid, got %v", err)
	}
}

func TestSQLSanitizeLiteral(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewSQLSanitizer(WithSQLMode(SQLModeLiteral))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize("O'Reilly")
	if err != nil {
		t.Fatalf("expected sanitized literal, got %v", err)
	}

	if output != "O''Reilly" {
		t.Fatalf("expected escaped literal, got %q", output)
	}

	_, err = sanitizer.Sanitize("bad\x00")
	if !errors.Is(err, ErrSQLLiteralInvalid) {
		t.Fatalf("expected ErrSQLLiteralInvalid, got %v", err)
	}
}

func TestSQLSanitizeLikePattern(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewSQLSanitizer(WithSQLMode(SQLModeLikePattern))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize(`50%_off\`)
	if err != nil {
		t.Fatalf("expected sanitized pattern, got %v", err)
	}

	if output != `50\%\_off\\` {
		t.Fatalf("expected escaped pattern, got %q", output)
	}
}

func TestSQLInjectionDetector(t *testing.T) {
	t.Parallel()

	detector, err := NewSQLInjectionDetector()
	if err != nil {
		t.Fatalf(errMsgDetector, err)
	}

	err = detector.Detect("1 OR 1=1; --")
	if !errors.Is(err, ErrSQLInjectionDetected) {
		t.Fatalf("expected ErrSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect("username")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
