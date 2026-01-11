package encoding

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-json"
	"github.com/hyp3rd/ewrap"
)

const (
	jsonDefaultMaxBytes = 1 << 20
)

// JSONOption configures JSON encoding and decoding.
type JSONOption func(*jsonOptions) error

type jsonOptions struct {
	maxBytes           int
	allowUnknownFields bool
	useNumber          bool
}

// EncodeJSON marshals a value using go-json with size bounds.
func EncodeJSON(value any, opts ...JSONOption) ([]byte, error) {
	cfg, err := resolveJSONOptions(opts)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(value)
	if err != nil {
		return nil, ewrap.Wrapf(err, "%v:", ErrJSONInvalid)
	}

	if len(data) > cfg.maxBytes {
		return nil, ErrJSONTooLarge
	}

	return data, nil
}

// DecodeJSON decodes JSON from a byte slice with size bounds.
func DecodeJSON(data []byte, value any, opts ...JSONOption) error {
	cfg, err := resolveJSONOptions(opts)
	if err != nil {
		return err
	}

	if value == nil || len(data) == 0 {
		return ErrJSONInvalid
	}

	if len(data) > cfg.maxBytes {
		return ErrJSONTooLarge
	}

	return decodeJSONBytes(data, value, cfg)
}

// DecodeJSONReader decodes JSON from a reader with size bounds.
func DecodeJSONReader(reader io.Reader, value any, opts ...JSONOption) error {
	cfg, err := resolveJSONOptions(opts)
	if err != nil {
		return err
	}

	if reader == nil || value == nil {
		return ErrJSONInvalid
	}

	data, err := readJSONInput(reader, cfg.maxBytes)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return ErrJSONInvalid
	}

	return decodeJSONBytes(data, value, cfg)
}

// WithJSONMaxBytes sets the maximum JSON payload size.
func WithJSONMaxBytes(maxBytes int) JSONOption {
	return func(cfg *jsonOptions) error {
		if maxBytes <= 0 {
			return ErrInvalidJSONConfig
		}

		cfg.maxBytes = maxBytes

		return nil
	}
}

// WithJSONAllowUnknownFields allows unknown fields during decode.
func WithJSONAllowUnknownFields(allow bool) JSONOption {
	return func(cfg *jsonOptions) error {
		cfg.allowUnknownFields = allow

		return nil
	}
}

// WithJSONUseNumber enables json.Number decoding for numbers.
func WithJSONUseNumber(useNumber bool) JSONOption {
	return func(cfg *jsonOptions) error {
		cfg.useNumber = useNumber

		return nil
	}
}

func resolveJSONOptions(opts []JSONOption) (jsonOptions, error) {
	cfg := jsonOptions{
		maxBytes:           jsonDefaultMaxBytes,
		allowUnknownFields: false,
		useNumber:          false,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return jsonOptions{}, err
		}
	}

	err := validateJSONOptions(cfg)
	if err != nil {
		return jsonOptions{}, err
	}

	return cfg, nil
}

func validateJSONOptions(cfg jsonOptions) error {
	if cfg.maxBytes <= 0 {
		return ErrInvalidJSONConfig
	}

	return nil
}

func decodeJSONBytes(data []byte, value any, cfg jsonOptions) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if !cfg.allowUnknownFields {
		decoder.DisallowUnknownFields()
	}

	if cfg.useNumber {
		decoder.UseNumber()
	}

	err := decoder.Decode(value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJSONInvalid, err)
	}

	err = ensureNoTrailingJSON(decoder)
	if err != nil {
		return err
	}

	return nil
}

func ensureNoTrailingJSON(decoder *json.Decoder) error {
	var extra any

	err := decoder.Decode(&extra)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return fmt.Errorf("%w: %w", ErrJSONTrailingData, err)
	}

	return ErrJSONTrailingData
}

func readJSONInput(reader io.Reader, maxBytes int) ([]byte, error) {
	limited := io.LimitReader(reader, int64(maxBytes)+1)

	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJSONInvalid, err)
	}

	if len(data) > maxBytes {
		return nil, ErrJSONTooLarge
	}

	return data, nil
}
