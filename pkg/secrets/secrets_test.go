package secrets

import "testing"

func TestSecretDetectorDetectAny(t *testing.T) {
	detector, err := NewSecretDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.DetectAny("AKIA1234567890ABCD12")
	if err != ErrSecretDetected {
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

func TestWithRedactionKeysValidation(t *testing.T) {
	t.Run("all whitespace keys should fail even with default keys", func(t *testing.T) {
		// This test verifies the fix for the validation inconsistency.
		// Even when cfg.keys has default keys, passing all-whitespace keys should fail.
		_, err := NewRedactor(WithRedactionKeys("   ", "\t", "\n"))
		if err != ErrInvalidRedactorConfig {
			t.Fatalf("expected ErrInvalidRedactorConfig when all keys are whitespace, got %v", err)
		}
	})

	t.Run("empty keys slice should fail", func(t *testing.T) {
		_, err := NewRedactor(WithRedactionKeys())
		if err != ErrInvalidRedactorConfig {
			t.Fatalf("expected ErrInvalidRedactorConfig for empty keys, got %v", err)
		}
	})

	t.Run("valid keys should succeed", func(t *testing.T) {
		redactor, err := NewRedactor(WithRedactionKeys("custom_key"))
		if err != nil {
			t.Fatalf("expected redactor with valid key, got %v", err)
		}

		fields := map[string]any{
			"custom_key": "secret",
			"other":      "public",
		}

		redacted := redactor.RedactFields(fields)
		if redacted["custom_key"] == "secret" {
			t.Fatalf("expected custom_key to be redacted")
		}
		if redacted["other"] != "public" {
			t.Fatalf("expected other field to remain unchanged")
		}
	})

	t.Run("mix of valid and invalid keys should succeed", func(t *testing.T) {
		// At least one valid key means the option should succeed
		redactor, err := NewRedactor(WithRedactionKeys("   ", "valid_key", "\t"))
		if err != nil {
			t.Fatalf("expected redactor when at least one key is valid, got %v", err)
		}

		fields := map[string]any{
			"valid_key": "secret",
		}

		redacted := redactor.RedactFields(fields)
		if redacted["valid_key"] == "secret" {
			t.Fatalf("expected valid_key to be redacted")
		}
	})
}
