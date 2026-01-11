package sanitize

import (
	"errors"
	"html"
	"testing"
)

func TestHTMLSanitizeEscape(t *testing.T) {
	sanitizer, err := NewHTMLSanitizer()
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	input := `<script>alert("x")</script>`

	output, err := sanitizer.Sanitize(input)
	if err != nil {
		t.Fatalf("expected sanitized html, got %v", err)
	}

	expected := html.EscapeString(input)
	if output != expected {
		t.Fatalf("expected %q, got %q", expected, output)
	}
}

func TestHTMLSanitizeStrip(t *testing.T) {
	sanitizer, err := NewHTMLSanitizer(WithHTMLMode(HTMLSanitizeStrip))
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	output, err := sanitizer.Sanitize("Hello <b>World</b>")
	if err != nil {
		t.Fatalf("expected sanitized html, got %v", err)
	}

	if output != "Hello World" {
		t.Fatalf("expected stripped text, got %q", output)
	}
}

func TestHTMLSanitizePolicy(t *testing.T) {
	sanitizer, err := NewHTMLSanitizer(WithHTMLPolicy(HTMLPolicyFunc(func(_ string) (string, error) {
		return "policy", nil
	})))
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	output, err := sanitizer.Sanitize("ignored")
	if err != nil {
		t.Fatalf("expected sanitized html, got %v", err)
	}

	if output != "policy" {
		t.Fatalf("expected policy output, got %q", output)
	}
}

func TestHTMLSanitizeMaxLength(t *testing.T) {
	sanitizer, err := NewHTMLSanitizer(WithHTMLMaxLength(1))
	if err != nil {
		t.Fatalf("expected sanitizer, got %v", err)
	}

	_, err = sanitizer.Sanitize("ab")
	if !errors.Is(err, ErrHTMLTooLong) {
		t.Fatalf("expected ErrHTMLTooLong, got %v", err)
	}
}
