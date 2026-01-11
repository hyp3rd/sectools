package encoding

import (
	"encoding/hex"
	"strings"
)

const (
	hexDefaultMaxLength = 4096
)

// HexOption configures hex encoding and decoding.
type HexOption func(*hexOptions) error

type hexOptions struct {
	maxLength int
}

// EncodeHex encodes data into a hex string.
func EncodeHex(data []byte, opts ...HexOption) (string, error) {
	cfg, err := resolveHexOptions(opts)
	if err != nil {
		return "", err
	}

	if hex.EncodedLen(len(data)) > cfg.maxLength {
		return "", ErrHexTooLong
	}

	return hex.EncodeToString(data), nil
}

// DecodeHex decodes a hex string into bytes.
func DecodeHex(input string, opts ...HexOption) ([]byte, error) {
	cfg, err := resolveHexOptions(opts)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(input) == "" {
		return nil, ErrHexEmpty
	}

	if containsWhitespace(input) {
		return nil, ErrHexInvalid
	}

	if len(input) > cfg.maxLength {
		return nil, ErrHexTooLong
	}

	decoded, err := hex.DecodeString(input)
	if err != nil {
		return nil, ErrHexInvalid
	}

	return decoded, nil
}

// WithHexMaxLength sets the maximum accepted hex string length.
func WithHexMaxLength(maxLength int) HexOption {
	return func(cfg *hexOptions) error {
		if maxLength <= 0 {
			return ErrInvalidHexConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

func resolveHexOptions(opts []HexOption) (hexOptions, error) {
	cfg := hexOptions{
		maxLength: hexDefaultMaxLength,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return hexOptions{}, err
		}
	}

	err := validateHexOptions(cfg)
	if err != nil {
		return hexOptions{}, err
	}

	return cfg, nil
}

func validateHexOptions(cfg hexOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidHexConfig
	}

	return nil
}
