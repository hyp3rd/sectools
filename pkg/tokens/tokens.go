package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/hyp3rd/ewrap"
)

const (
	bitsPerByte                = 8
	tokenDefaultMinEntropyBits = 128
	tokenDefaultMaxLength      = 4096
)

// TokenEncoding defines the string encoding for tokens.
type TokenEncoding int

const (
	// TokenEncodingBase64URL encodes tokens using base64 URL encoding without padding.
	TokenEncodingBase64URL TokenEncoding = iota
	// TokenEncodingHex encodes tokens using hexadecimal encoding.
	TokenEncodingHex
)

// TokenOption configures token generation and validation.
type TokenOption func(*tokenOptions) error

type tokenOptions struct {
	encoding       TokenEncoding
	minEntropyBits int
	minBytes       int
	maxLength      int
}

// TokenGenerator generates cryptographically secure tokens.
// Instances of TokenGenerator contain only immutable configuration and can be safely
// used concurrently by multiple goroutines.
type TokenGenerator struct {
	opts tokenOptions
}

// TokenValidator validates token strings.
// Instances of TokenValidator contain only immutable configuration and can be safely
// used concurrently by multiple goroutines.
type TokenValidator struct {
	opts tokenOptions
}

// NewGenerator constructs a token generator with safe defaults.
func NewGenerator(opts ...TokenOption) (*TokenGenerator, error) {
	cfg := defaultTokenOptions()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateTokenOptions(cfg)
	if err != nil {
		return nil, err
	}

	return &TokenGenerator{opts: cfg}, nil
}

// NewValidator constructs a token validator with safe defaults.
func NewValidator(opts ...TokenOption) (*TokenValidator, error) {
	cfg := defaultTokenOptions()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateTokenOptions(cfg)
	if err != nil {
		return nil, err
	}

	return &TokenValidator{opts: cfg}, nil
}

// WithTokenEncoding sets the token encoding.
func WithTokenEncoding(encoding TokenEncoding) TokenOption {
	return func(cfg *tokenOptions) error {
		if encoding != TokenEncodingBase64URL && encoding != TokenEncodingHex {
			return ErrInvalidTokenConfig
		}

		cfg.encoding = encoding

		return nil
	}
}

// WithTokenMinEntropyBits sets the minimum entropy bits required.
func WithTokenMinEntropyBits(bits int) TokenOption {
	return func(cfg *tokenOptions) error {
		if bits <= 0 {
			return ErrInvalidTokenConfig
		}

		cfg.minEntropyBits = bits

		return nil
	}
}

// WithTokenMinBytes sets the minimum decoded token length in bytes.
func WithTokenMinBytes(minBytes int) TokenOption {
	return func(cfg *tokenOptions) error {
		if minBytes <= 0 {
			return ErrInvalidTokenConfig
		}

		cfg.minBytes = minBytes

		return nil
	}
}

// WithTokenMaxLength sets the maximum accepted token length in characters.
func WithTokenMaxLength(maxLength int) TokenOption {
	return func(cfg *tokenOptions) error {
		if maxLength <= 0 {
			return ErrInvalidTokenConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// Generate produces a new token encoded as a string.
func (g *TokenGenerator) Generate() (string, error) {
	raw, err := g.GenerateBytes()
	if err != nil {
		return "", err
	}

	token, err := encodeToken(raw, g.opts.encoding)
	if err != nil {
		return "", err
	}

	if len(token) > g.opts.maxLength {
		return "", ErrTokenTooLong
	}

	return token, nil
}

// GenerateBytes produces raw token bytes.
func (g *TokenGenerator) GenerateBytes() ([]byte, error) {
	length := requiredBytes(g.opts)
	if length <= 0 {
		return nil, ErrInvalidTokenConfig
	}

	raw := make([]byte, length)

	_, err := rand.Read(raw)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	return raw, nil
}

// Validate checks a token string and returns the decoded bytes.
func (v *TokenValidator) Validate(token string) ([]byte, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrTokenEmpty
	}

	if len(token) > v.opts.maxLength {
		return nil, ErrTokenTooLong
	}

	if containsSpace(token) {
		return nil, ErrTokenInvalid
	}

	decoded, err := decodeToken(token, v.opts.encoding)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if v.opts.minBytes > 0 && len(decoded) < v.opts.minBytes {
		return nil, ErrTokenTooShort
	}

	if len(decoded)*bitsPerByte < v.opts.minEntropyBits {
		return nil, ErrTokenInsufficientEntropy
	}

	return decoded, nil
}

func defaultTokenOptions() tokenOptions {
	return tokenOptions{
		encoding:       TokenEncodingBase64URL,
		minEntropyBits: tokenDefaultMinEntropyBits,
		maxLength:      tokenDefaultMaxLength,
	}
}

func validateTokenOptions(cfg tokenOptions) error {
	if cfg.minEntropyBits <= 0 || cfg.maxLength <= 0 || cfg.minBytes < 0 {
		return ErrInvalidTokenConfig
	}

	if cfg.encoding != TokenEncodingBase64URL && cfg.encoding != TokenEncodingHex {
		return ErrInvalidTokenConfig
	}

	required := requiredBytes(cfg)
	if required <= 0 {
		return ErrInvalidTokenConfig
	}

	if encodedLength(cfg.encoding, required) > cfg.maxLength {
		return ErrInvalidTokenConfig
	}

	return nil
}

func requiredBytes(cfg tokenOptions) int {
	required := cfg.minEntropyBits / bitsPerByte
	if cfg.minEntropyBits%bitsPerByte != 0 {
		required++
	}

	if cfg.minBytes > required {
		required = cfg.minBytes
	}

	return required
}

func encodedLength(encoding TokenEncoding, bytes int) int {
	switch encoding {
	case TokenEncodingBase64URL:
		return base64.RawURLEncoding.EncodedLen(bytes)
	case TokenEncodingHex:
		return hex.EncodedLen(bytes)
	default:
		return 0
	}
}

func encodeToken(raw []byte, encoding TokenEncoding) (string, error) {
	switch encoding {
	case TokenEncodingBase64URL:
		return base64.RawURLEncoding.EncodeToString(raw), nil
	case TokenEncodingHex:
		return hex.EncodeToString(raw), nil
	default:
		return "", ErrInvalidTokenConfig
	}
}

func decodeToken(token string, encoding TokenEncoding) ([]byte, error) {
	switch encoding {
	case TokenEncodingBase64URL:
		data, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, ewrap.Wrap(err, "failed to decode base64 URL token")
		}

		return data, nil
	case TokenEncodingHex:
		data, err := hex.DecodeString(token)
		if err != nil {
			return nil, ewrap.Wrap(err, "failed to decode hex token")
		}

		return data, nil
	default:
		return nil, ErrInvalidTokenConfig
	}
}

func containsSpace(value string) bool {
	return strings.IndexFunc(value, unicode.IsSpace) >= 0
}
