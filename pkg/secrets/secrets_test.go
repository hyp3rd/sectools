package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestSecretDetectorDetectAny(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.DetectAny("AKIA1234567890ABCD12")
	if !errors.Is(err, ErrSecretDetected) {
		t.Fatalf("expected ErrSecretDetected, got %v", err)
	}
}

func TestSecretDetectorRedact(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	input := "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"

	output, matches, err := detector.Redact(input)
	if err != nil {
		t.Fatalf("expected redacted, got %v", err)
	}

	if len(matches) == 0 {
		t.Fatalf("expected matches, got none")
	}

	if output == input {
		t.Fatalf("expected redacted output")
	}
}

func TestRedactorKeys(t *testing.T) {
	redactor, err := NewRedactor()
	if err != nil {
		t.Fatalf("expected redactor, got %v", err)
	}

	fields := map[string]any{
		"password": "secret",
		"user":     "alice",
	}

	redacted := redactor.RedactFields(fields)
	if redacted["password"] == "secret" {
		t.Fatalf("expected password redacted")
	}

	if redacted["user"] != "alice" {
		t.Fatalf("expected user intact")
	}
}

func TestRedactorDetector(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	redactor, err := NewRedactor(WithRedactionDetector(detector))
	if err != nil {
		t.Fatalf("expected redactor, got %v", err)
	}

	fields := map[string]any{
		"note": "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
	}

	redacted := redactor.RedactFields(fields)
	if redacted["note"] == fields["note"] {
		t.Fatalf("expected detector to redact note")
	}
}

// TestSecretDetectorInputTooLong tests ErrSecretInputTooLong error.
func TestSecretDetectorInputTooLong(t *testing.T) {
	detector, err := NewSecretDetector(WithSecretMaxLength(10))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	longInput := strings.Repeat("a", 11)

	_, err = detector.Detect(longInput)
	if !errors.Is(err, ErrSecretInputTooLong) {
		t.Fatalf("expected ErrSecretInputTooLong, got %v", err)
	}

	err = detector.DetectAny(longInput)
	if !errors.Is(err, ErrSecretInputTooLong) {
		t.Fatalf("expected ErrSecretInputTooLong for DetectAny, got %v", err)
	}

	_, _, err = detector.Redact(longInput)
	if !errors.Is(err, ErrSecretInputTooLong) {
		t.Fatalf("expected ErrSecretInputTooLong for Redact, got %v", err)
	}
}

// TestSecretDetectorInvalidConfig tests invalid detector configurations.
func TestSecretDetectorInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		opts []SecretDetectOption
	}{
		{
			name: "invalid max length",
			opts: []SecretDetectOption{WithSecretMaxLength(0)},
		},
		{
			name: "negative max length",
			opts: []SecretDetectOption{WithSecretMaxLength(-1)},
		},
		{
			name: "empty mask",
			opts: []SecretDetectOption{WithSecretMask("")},
		},
		{
			name: "whitespace mask",
			opts: []SecretDetectOption{WithSecretMask("   ")},
		},
		{
			name: "empty patterns",
			opts: []SecretDetectOption{WithSecretPatterns()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretDetector(tt.opts...)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestRedactorInvalidConfig tests invalid redactor configurations.
func TestRedactorInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		opts []RedactorOption
	}{
		{
			name: "empty redaction mask",
			opts: []RedactorOption{WithRedactionMask("")},
		},
		{
			name: "whitespace redaction mask",
			opts: []RedactorOption{WithRedactionMask("   ")},
		},
		{
			name: "nil detector",
			opts: []RedactorOption{WithRedactionDetector(nil)},
		},
		{
			name: "zero max depth",
			opts: []RedactorOption{WithRedactionMaxDepth(0)},
		},
		{
			name: "negative max depth",
			opts: []RedactorOption{WithRedactionMaxDepth(-1)},
		},
		{
			name: "empty keys",
			opts: []RedactorOption{WithRedactionKeys()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRedactor(tt.opts...)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestSecretDetectorEdgeCases tests edge cases like empty and nil values.
func TestSecretDetectorEdgeCases(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	t.Run("empty string", func(t *testing.T) {
		matches, err := detector.Detect("")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if matches != nil {
			t.Fatalf("expected nil matches, got %v", matches)
		}
	})

	t.Run("whitespace only", func(t *testing.T) {
		matches, err := detector.Detect("   ")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if matches != nil {
			t.Fatalf("expected nil matches, got %v", matches)
		}
	})

	t.Run("no secrets", func(t *testing.T) {
		matches, err := detector.Detect("hello world")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(matches) != 0 {
			t.Fatalf("expected no matches, got %v", matches)
		}
	})
}

// TestRedactorEdgeCases tests edge cases for redactor.
func TestRedactorEdgeCases(t *testing.T) {
	redactor, err := NewRedactor()
	if err != nil {
		t.Fatalf("expected redactor, got %v", err)
	}

	t.Run("nil fields", func(t *testing.T) {
		result := redactor.RedactFields(nil)
		if result != nil {
			t.Fatalf("expected nil result, got %v", result)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		fields := map[string]any{}

		result := redactor.RedactFields(fields)
		if len(result) != 0 {
			t.Fatalf("expected empty map, got %v", result)
		}
	})

	t.Run("empty string value", func(t *testing.T) {
		result := redactor.RedactString("")
		if result != "" {
			t.Fatalf("expected empty string, got %q", result)
		}
	})
}

// TestWithSecretPattern tests the WithSecretPattern option.
func TestWithSecretPattern(t *testing.T) {
	detector, err := NewSecretDetector(
		WithSecretPattern("custom-pattern", `custom-[0-9]{4}`),
	)
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	input := "My custom token is custom-1234"

	matches, err := detector.Detect(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	found := false

	for _, match := range matches {
		if match.Pattern == "custom-pattern" && match.Value == "custom-1234" {
			found = true

			break
		}
	}

	if !found {
		t.Fatalf("expected to find custom-pattern match")
	}
}

// TestWithSecretPatterns tests the WithSecretPatterns option.
func TestWithSecretPatterns(t *testing.T) {
	patterns := []SecretPattern{
		{Name: "test-pattern-1", Pattern: `test-[0-9]{3}`},
		{Name: "test-pattern-2", Pattern: `secret-[a-z]{3}`},
	}

	detector, err := NewSecretDetector(WithSecretPatterns(patterns...))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	input := "Found test-123 and secret-abc"

	matches, err := detector.Detect(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

// TestWithSecretMaxLength tests the WithSecretMaxLength option.
func TestWithSecretMaxLength(t *testing.T) {
	maxLen := 20

	detector, err := NewSecretDetector(WithSecretMaxLength(maxLen))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	t.Run("within limit", func(t *testing.T) {
		input := "short text"

		_, err := detector.Detect(input)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		input := strings.Repeat("a", maxLen+1)

		_, err := detector.Detect(input)
		if !errors.Is(err, ErrSecretInputTooLong) {
			t.Fatalf("expected ErrSecretInputTooLong, got %v", err)
		}
	})
}

// TestWithSecretMask tests the WithSecretMask option.
func TestWithSecretMask(t *testing.T) {
	customMask := "***HIDDEN***"

	detector, err := NewSecretDetector(WithSecretMask(customMask))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	input := "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"

	output, matches, err := detector.Redact(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(matches) == 0 {
		t.Fatalf("expected matches, got none")
	}

	if !strings.Contains(output, customMask) {
		t.Fatalf("expected output to contain custom mask %q, got %q", customMask, output)
	}
}

// TestNestedStructureRedaction tests redaction of nested structures.
func TestNestedStructureRedaction(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	redactor, err := NewRedactor(WithRedactionDetector(detector))
	if err != nil {
		t.Fatalf("expected redactor, got %v", err)
	}

	t.Run("maps within maps", func(t *testing.T) {
		fields := map[string]any{
			"user": "alice",
			"auth": map[string]any{
				"password": "secret123",
				"token":    "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
				"metadata": map[string]any{
					"api_key": "sensitive",
					"name":    "test",
				},
			},
		}

		redacted := redactor.RedactFields(fields)

		if redacted["user"] != "alice" {
			t.Fatalf("expected user intact")
		}

		auth, ok := redacted["auth"].(map[string]any)
		if !ok {
			t.Fatalf("expected auth to be map[string]any")
		}

		if auth["password"] == "secret123" {
			t.Fatalf("expected password redacted in nested map")
		}

		if auth["token"] == "ghp_abcdefghijklmnopqrstuvwxyz1234567890" {
			t.Fatalf("expected token redacted in nested map")
		}

		metadata, ok := auth["metadata"].(map[string]any)
		if !ok {
			t.Fatalf("expected metadata to be map[string]any")
		}

		if metadata["api_key"] == "sensitive" {
			t.Fatalf("expected api_key redacted in deeply nested map")
		}

		if metadata["name"] != "test" {
			t.Fatalf("expected name intact in deeply nested map")
		}
	})

	t.Run("slices within maps", func(t *testing.T) {
		fields := map[string]any{
			"users": []any{
				map[string]any{
					"name":     "alice",
					"password": "secret1",
				},
				map[string]any{
					"name":  "bob",
					"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
				},
			},
		}

		redacted := redactor.RedactFields(fields)

		users, ok := redacted["users"].([]any)
		if !ok {
			t.Fatalf("expected users to be []any")
		}

		if len(users) != 2 {
			t.Fatalf("expected 2 users, got %d", len(users))
		}

		user1, ok := users[0].(map[string]any)
		if !ok {
			t.Fatalf("expected user1 to be map[string]any")
		}

		if user1["name"] != "alice" {
			t.Fatalf("expected alice's name intact")
		}

		if user1["password"] == "secret1" {
			t.Fatalf("expected alice's password redacted")
		}

		user2, ok := users[1].(map[string]any)
		if !ok {
			t.Fatalf("expected user2 to be map[string]any")
		}

		if user2["token"] == "ghp_abcdefghijklmnopqrstuvwxyz1234567890" {
			t.Fatalf("expected bob's token redacted")
		}
	})
}

// TestWithRedactionKeys tests the WithRedactionKeys option.
func TestWithRedactionKeys(t *testing.T) {
	t.Run("add custom keys", func(t *testing.T) {
		redactor, err := NewRedactor(
			WithRedactionKeys("custom_secret", "private_data"),
		)
		if err != nil {
			t.Fatalf("expected redactor, got %v", err)
		}

		fields := map[string]any{
			"custom_secret": "sensitive",
			"private_data":  "confidential",
			"public_info":   "visible",
		}

		redacted := redactor.RedactFields(fields)

		if redacted["custom_secret"] == "sensitive" {
			t.Fatalf("expected custom_secret redacted")
		}

		if redacted["private_data"] == "confidential" {
			t.Fatalf("expected private_data redacted")
		}

		if redacted["public_info"] != "visible" {
			t.Fatalf("expected public_info intact")
		}
	})

	t.Run("case insensitive keys", func(t *testing.T) {
		redactor, err := NewRedactor(
			WithRedactionKeys("MySecret"),
		)
		if err != nil {
			t.Fatalf("expected redactor, got %v", err)
		}

		fields := map[string]any{
			"mysecret": "value1",
			"MYSECRET": "value2",
			"MySecret": "value3",
		}

		redacted := redactor.RedactFields(fields)

		if redacted["mysecret"] == "value1" {
			t.Fatalf("expected mysecret redacted")
		}

		if redacted["MYSECRET"] == "value2" {
			t.Fatalf("expected MYSECRET redacted")
		}

		if redacted["MySecret"] == "value3" {
			t.Fatalf("expected MySecret redacted")
		}
	})
}

// TestWithRedactionMaxDepth tests the WithRedactionMaxDepth option.
func TestWithRedactionMaxDepth(t *testing.T) {
	t.Run("depth limit prevents deep redaction", func(t *testing.T) {
		redactor, err := NewRedactor(WithRedactionMaxDepth(2))
		if err != nil {
			t.Fatalf("expected redactor, got %v", err)
		}

		// Create a deeply nested structure (depth > 2)
		fields := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"password": "should_not_redact",
					},
				},
			},
		}

		redacted := redactor.RedactFields(fields)

		level1, ok := redacted["level1"].(map[string]any)
		if !ok {
			t.Fatalf("expected level1 to be map[string]any")
		}

		level2, ok := level1["level2"].(map[string]any)
		if !ok {
			t.Fatalf("expected level2 to be map[string]any")
		}

		level3, ok := level2["level3"].(map[string]any)
		if !ok {
			t.Fatalf("expected level3 to be map[string]any")
		}

		// At depth 3, the password should not be redacted due to max depth limit
		if level3["password"] != "should_not_redact" {
			t.Fatalf("expected password to remain intact at depth > maxDepth")
		}
	})

	t.Run("within depth limit redacts properly", func(t *testing.T) {
		redactor, err := NewRedactor(WithRedactionMaxDepth(3))
		if err != nil {
			t.Fatalf("expected redactor, got %v", err)
		}

		fields := map[string]any{
			"level1": map[string]any{
				"password": "should_redact",
			},
		}

		redacted := redactor.RedactFields(fields)

		level1, ok := redacted["level1"].(map[string]any)
		if !ok {
			t.Fatalf("expected level1 to be map[string]any")
		}

		if level1["password"] == "should_redact" {
			t.Fatalf("expected password to be redacted within depth limit")
		}
	})
}
