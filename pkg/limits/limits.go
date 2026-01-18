package limits

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/hyp3rd/sectools/pkg/converters"
	sectencoding "github.com/hyp3rd/sectools/pkg/encoding"
)

const (
	limitsDefaultMaxBytes = 1 << 20
)

// Option configures size limits and decoding behavior.
type Option func(*config) error

type config struct {
	maxBytes               int
	yamlAllowUnknownFields bool
}

// ReadAll reads the entire input, enforcing the configured size limit.
func ReadAll(reader io.Reader, opts ...Option) ([]byte, error) {
	cfg, err := resolveConfig(opts)
	if err != nil {
		return nil, err
	}

	return readAll(reader, cfg.maxBytes)
}

// DecodeJSON decodes JSON with size bounds and strict defaults.
func DecodeJSON(reader io.Reader, value any, opts ...Option) error {
	cfg, err := resolveConfig(opts)
	if err != nil {
		return err
	}

	if reader == nil || value == nil {
		return ErrInvalidLimitInput
	}

	data, err := readAll(reader, cfg.maxBytes)
	if err != nil {
		return err
	}

	return sectencoding.DecodeJSON(data, value, sectencoding.WithJSONMaxBytes(cfg.maxBytes))
}

// DecodeYAML decodes YAML with size bounds.
// Unknown fields are rejected by default unless WithYAMLAllowUnknownFields(true) is set.
func DecodeYAML(reader io.Reader, value any, opts ...Option) error {
	cfg, err := resolveConfig(opts)
	if err != nil {
		return err
	}

	if reader == nil || value == nil {
		return ErrInvalidLimitInput
	}

	data, err := readAll(reader, cfg.maxBytes)
	if err != nil {
		return err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(!cfg.yamlAllowUnknownFields)

	err = decoder.Decode(value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecodeFailed, err)
	}

	var extra any

	err = decoder.Decode(&extra)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return fmt.Errorf("%w: %w", ErrDecodeFailed, err)
	}

	return ErrDecodeFailed
}

// DecodeXML decodes XML with size bounds.
func DecodeXML(reader io.Reader, value any, opts ...Option) error {
	cfg, err := resolveConfig(opts)
	if err != nil {
		return err
	}

	if reader == nil || value == nil {
		return ErrInvalidLimitInput
	}

	data, err := readAll(reader, cfg.maxBytes)
	if err != nil {
		return err
	}

	err = xml.Unmarshal(data, value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecodeFailed, err)
	}

	return nil
}

// WithMaxBytes sets the maximum allowed input size in bytes.
func WithMaxBytes(maxBytes int) Option {
	return func(cfg *config) error {
		if maxBytes <= 0 {
			return ErrInvalidLimitConfig
		}

		cfg.maxBytes = maxBytes

		return nil
	}
}

// WithYAMLAllowUnknownFields permits unknown YAML fields during decode.
func WithYAMLAllowUnknownFields(allow bool) Option {
	return func(cfg *config) error {
		cfg.yamlAllowUnknownFields = allow

		return nil
	}
}

func resolveConfig(opts []Option) (config, error) {
	cfg := config{
		maxBytes:               limitsDefaultMaxBytes,
		yamlAllowUnknownFields: false,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return config{}, err
		}
	}

	if cfg.maxBytes <= 0 {
		return config{}, ErrInvalidLimitConfig
	}

	return cfg, nil
}

func readAll(reader io.Reader, maxBytes int) ([]byte, error) {
	if reader == nil {
		return nil, ErrInvalidLimitInput
	}

	maxBytes64, err := converters.ToInt64(maxBytes)
	if err != nil || maxBytes64 <= 0 {
		return nil, ErrInvalidLimitConfig
	}

	limited := io.LimitReader(reader, maxBytes64+1)

	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	if len(data) > maxBytes {
		return nil, ErrLimitExceeded
	}

	return data, nil
}
