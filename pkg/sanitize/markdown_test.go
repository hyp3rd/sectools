package sanitize

import (
	"errors"
	"html"
	"testing"
)

func TestMarkdownSanitizeEscape(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewMarkdownSanitizer()
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	input := "<b>hello</b>"

	output, err := sanitizer.Sanitize(input)
	if err != nil {
		t.Fatalf("expected sanitized markdown, got %v", err)
	}

	expected := html.EscapeString(input)
	if output != expected {
		t.Fatalf("expected %q, got %q", expected, output)
	}
}

func TestMarkdownAllowRawHTML(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewMarkdownSanitizer(WithMarkdownAllowRawHTML(true))
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	input := "<b>hello</b>"

	output, err := sanitizer.Sanitize(input)
	if err != nil {
		t.Fatalf("expected sanitized markdown, got %v", err)
	}

	if output != input {
		t.Fatalf("expected raw html, got %q", output)
	}
}

func TestMarkdownMaxLength(t *testing.T) {
	t.Parallel()

	sanitizer, err := NewMarkdownSanitizer(WithMarkdownMaxLength(1))
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	_, err = sanitizer.Sanitize("ab")
	if !errors.Is(err, ErrMarkdownTooLong) {
		t.Fatalf("expected ErrMarkdownTooLong, got %v", err)
	}
}
