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
