package encoding

import (
	"encoding/base64"
	"strings"
)

const (
	base64DefaultMaxLength = 4096
)

// Base64Encoding identifies a base64 encoding variant.
type Base64Encoding int

const (
	// Base64EncodingRawURL uses URL-safe base64 without padding.
	Base64EncodingRawURL Base64Encoding = iota
	// Base64EncodingRawStd uses standard base64 without padding.
	Base64EncodingRawStd
	// Base64EncodingURL uses URL-safe base64 with padding.
	Base64EncodingURL
	// Base64EncodingStd uses standard base64 with padding.
	Base64EncodingStd
)

// Base64Option configures base64 encoding and decoding.
type Base64Option func(*base64Options) error

type base64Options struct {
	encoding  *base64.Encoding
	maxLength int
}

// EncodeBase64 encodes data using the configured base64 encoding.
func EncodeBase64(data []byte, opts ...Base64Option) (string, error) {
	cfg, err := resolveBase64Options(opts)
	if err != nil {
		return "", err
	}

	if cfg.encoding.EncodedLen(len(data)) > cfg.maxLength {
		return "", ErrBase64TooLong
	}

	return cfg.encoding.EncodeToString(data), nil
}

// DecodeBase64 decodes a base64-encoded string.
func DecodeBase64(input string, opts ...Base64Option) ([]byte, error) {
	cfg, err := resolveBase64Options(opts)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(input) == "" {
		return nil, ErrBase64Empty
	}

	if containsWhitespace(input) {
		return nil, ErrBase64Invalid
	}

	if len(input) > cfg.maxLength {
		return nil, ErrBase64TooLong
	}

	decoded, err := cfg.encoding.DecodeString(input)
	if err != nil {
		return nil, ErrBase64Invalid
	}

	return decoded, nil
}

// WithBase64Encoding sets the base64 encoding variant.
func WithBase64Encoding(encoding Base64Encoding) Base64Option {
	return func(cfg *base64Options) error {
		enc, err := base64Encoding(encoding)
		if err != nil {
			return err
		}

		cfg.encoding = enc

		return nil
	}
}

// WithBase64MaxLength sets the maximum accepted base64 string length.
func WithBase64MaxLength(maxLength int) Base64Option {
	return func(cfg *base64Options) error {
		if maxLength <= 0 {
			return ErrInvalidBase64Config
		}

		cfg.maxLength = maxLength

		return nil
	}
}

func resolveBase64Options(opts []Base64Option) (base64Options, error) {
	cfg := base64Options{
		encoding:  base64.RawURLEncoding,
		maxLength: base64DefaultMaxLength,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return base64Options{}, err
		}
	}

	err := validateBase64Options(cfg)
	if err != nil {
		return base64Options{}, err
	}

	return cfg, nil
}

func validateBase64Options(cfg base64Options) error {
	if cfg.encoding == nil || cfg.maxLength <= 0 {
		return ErrInvalidBase64Config
	}

	return nil
}

func base64Encoding(encoding Base64Encoding) (*base64.Encoding, error) {
	switch encoding {
	case Base64EncodingRawURL:
		return base64.RawURLEncoding, nil
	case Base64EncodingRawStd:
		return base64.RawStdEncoding, nil
	case Base64EncodingURL:
		return base64.URLEncoding, nil
	case Base64EncodingStd:
		return base64.StdEncoding, nil
	default:
		return nil, ErrInvalidBase64Config
	}
}
