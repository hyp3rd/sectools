package sanitize

import (
	"errors"
	"testing"
)

const errMsgUnexpected = "expected sanitizer, got %v"

func TestFilenameSanitizeBasic(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewFilenameSanitizer()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize("report.pdf")
	if err != nil {
		t.Fatalf("expected sanitized filename, got %v", err)
	}

	if output != "report.pdf" {
		t.Fatalf("expected report.pdf, got %q", output)
	}
}

func TestFilenameSanitizeLeadingDot(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewFilenameSanitizer()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize(".env")
	if err != nil {
		t.Fatalf("expected sanitized filename, got %v", err)
	}

	if output != "_env" {
		t.Fatalf("expected _env, got %q", output)
	}
}

func TestFilenameSanitizeSeparators(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewFilenameSanitizer()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	output, err := sanitizer.Sanitize("foo/bar")
	if err != nil {
		t.Fatalf("expected sanitized filename, got %v", err)
	}

	if output != "foo_bar" {
		t.Fatalf("expected foo_bar, got %q", output)
	}
}

func TestFilenameSanitizeEmpty(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewFilenameSanitizer()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	_, err = sanitizer.Sanitize("   ")
	if !errors.Is(err, ErrFilenameEmpty) {
		t.Fatalf("expected ErrFilenameEmpty, got %v", err)
	}
}

func TestFilenameSanitizeMaxLength(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewFilenameSanitizer(WithFilenameMaxLength(3))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	_, err = sanitizer.Sanitize("abcd")
	if !errors.Is(err, ErrFilenameTooLong) {
		t.Fatalf("expected ErrFilenameTooLong, got %v", err)
	}
}
