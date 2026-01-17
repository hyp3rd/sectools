package encoding

import (
	"errors"
	"strings"
	"testing"
)

const errMsgUnexpected = "expected decoded, got %v"

func TestBase64EncodeDecode(t *testing.T) {
	t.Parallel()

	input := []byte("hello")

	encoded, err := EncodeBase64(input)
	if err != nil {
		t.Fatalf("expected encoded, got %v", err)
	}

	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if string(decoded) != string(input) {
		t.Fatalf("expected %q, got %q", input, decoded)
	}
}

func TestBase64InvalidWhitespace(t *testing.T) {
	t.Parallel()

	_, err := DecodeBase64("a b")
	if !errors.Is(err, ErrBase64Invalid) {
		t.Fatalf("expected ErrBase64Invalid, got %v", err)
	}
}

func TestBase64MaxLength(t *testing.T) {
	t.Parallel()

	_, err := EncodeBase64([]byte("hello"), WithBase64MaxLength(4))
	if !errors.Is(err, ErrBase64TooLong) {
		t.Fatalf("expected ErrBase64TooLong, got %v", err)
	}
}

func TestHexEncodeDecode(t *testing.T) {
	t.Parallel()

	input := []byte("hello")

	encoded, err := EncodeHex(input)
	if err != nil {
		t.Fatalf("expected encoded, got %v", err)
	}

	decoded, err := DecodeHex(encoded)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if string(decoded) != string(input) {
		t.Fatalf("expected %q, got %q", input, decoded)
	}
}

func TestHexInvalid(t *testing.T) {
	t.Parallel()

	_, err := DecodeHex("zz")
	if !errors.Is(err, ErrHexInvalid) {
		t.Fatalf("expected ErrHexInvalid, got %v", err)
	}
}

func TestHexMaxLength(t *testing.T) {
	t.Parallel()

	_, err := EncodeHex([]byte("hello"), WithHexMaxLength(4))
	if !errors.Is(err, ErrHexTooLong) {
		t.Fatalf("expected ErrHexTooLong, got %v", err)
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	data, err := EncodeJSON(payload{Name: "alpha"})
	if err != nil {
		t.Fatalf("expected json, got %v", err)
	}

	var result payload

	err = DecodeJSON(data, &result)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if result.Name != "alpha" {
		t.Fatalf("expected alpha, got %q", result.Name)
	}
}

func TestDecodeJSONUnknownField(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var result payload

	err := DecodeJSON([]byte(`{"name":"alpha","extra":true}`), &result)
	if !errors.Is(err, ErrJSONInvalid) {
		t.Fatalf("expected ErrJSONInvalid, got %v", err)
	}
}

func TestDecodeJSONAllowUnknown(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var result payload

	err := DecodeJSON(
		[]byte(`{"name":"alpha","extra":true}`),
		&result,
		WithJSONAllowUnknownFields(true),
	)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}
}

func TestDecodeJSONTrailingData(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var result payload

	err := DecodeJSON([]byte(`{"name":"alpha"}{"name":"beta"}`), &result)
	if !errors.Is(err, ErrJSONTrailingData) {
		t.Fatalf("expected ErrJSONTrailingData, got %v", err)
	}
}

func TestDecodeJSONMaxBytes(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	var result payload

	err := DecodeJSON([]byte(`{"name":"alpha"}`), &result, WithJSONMaxBytes(4))
	if !errors.Is(err, ErrJSONTooLarge) {
		t.Fatalf("expected ErrJSONTooLarge, got %v", err)
	}
}

func TestDecodeJSONReader(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}

	reader := strings.NewReader(`{"name":"alpha"}`)

	var result payload

	err := DecodeJSONReader(reader, &result)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if result.Name != "alpha" {
		t.Fatalf("expected alpha, got %q", result.Name)
	}
}
