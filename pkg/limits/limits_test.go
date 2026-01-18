package limits

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const payloadName = "sectools"

func TestReadAllWithinLimit(t *testing.T) {
	t.Parallel()

	data, err := ReadAll(strings.NewReader("hello"), WithMaxBytes(10))
	if err != nil {
		t.Fatalf("expected data, got %v", err)
	}

	if string(data) != "hello" {
		t.Fatalf("unexpected data: %s", data)
	}
}

func TestReadAllTooLarge(t *testing.T) {
	t.Parallel()
	//nolint:revive
	_, err := ReadAll(strings.NewReader("hello"), WithMaxBytes(4))
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestReadAllInvalidInput(t *testing.T) {
	t.Parallel()

	_, err := ReadAll(nil)
	if !errors.Is(err, ErrInvalidLimitInput) {
		t.Fatalf("expected ErrInvalidLimitInput, got %v", err)
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var out payload
	//nolint:revive
	err := DecodeJSON(strings.NewReader(`{"name":"sectools"}`), &out, WithMaxBytes(128))
	if err != nil {
		t.Fatalf("expected decode, got %v", err)
	}

	if out.Name != payloadName {
		t.Fatalf("unexpected name: %s", out.Name)
	}
}

func TestDecodeJSONTooLarge(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var out payload
	//nolint:revive
	err := DecodeJSON(strings.NewReader(`{"name":"sectools"}`), &out, WithMaxBytes(5))
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestDecodeYAMLUnknownFields(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `yaml:"name"`
	}

	var out payload
	//nolint:revive
	err := DecodeYAML(strings.NewReader("name: sectools\nextra: field\n"), &out, WithMaxBytes(256))
	if !errors.Is(err, ErrDecodeFailed) {
		t.Fatalf("expected ErrDecodeFailed, got %v", err)
	}
}

func TestDecodeYAMLAllowUnknownFields(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `yaml:"name"`
	}

	var out payload

	err := DecodeYAML(
		strings.NewReader("name: sectools\nextra: field\n"),
		&out,
		WithMaxBytes(256), //nolint:revive
		WithYAMLAllowUnknownFields(true),
	)
	if err != nil {
		t.Fatalf("expected decode, got %v", err)
	}

	if out.Name != payloadName {
		t.Fatalf("unexpected name: %s", out.Name)
	}
}

func TestDecodeXML(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `xml:"name"`
	}

	var out payload
	//nolint:revive
	err := DecodeXML(strings.NewReader(fmt.Sprintf("<payload><name>%s</name></payload>", payloadName)), &out, WithMaxBytes(256))
	if err != nil {
		t.Fatalf("expected decode, got %v", err)
	}

	if out.Name != payloadName {
		t.Fatalf("unexpected name: %s", out.Name)
	}
}

func TestDecodeInvalidInput(t *testing.T) {
	t.Parallel()

	var out struct{}

	err := DecodeJSON(nil, &out)
	if !errors.Is(err, ErrInvalidLimitInput) {
		t.Fatalf("expected ErrInvalidLimitInput, got %v", err)
	}

	err = DecodeJSON(strings.NewReader("{}"), nil)
	if !errors.Is(err, ErrInvalidLimitInput) {
		t.Fatalf("expected ErrInvalidLimitInput, got %v", err)
	}
}
