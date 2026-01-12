package secrets

import (
	"strings"
)

const (
	redactionDefaultMaxDepth = 6
)

// RedactorOption configures redaction behavior.
type RedactorOption func(*redactorOptions) error

type redactorOptions struct {
	mask     string
	keys     map[string]struct{}
	detector *SecretDetector
	maxDepth int
}

// Redactor redacts secrets from structured fields.
type Redactor struct {
	opts redactorOptions
}

// NewRedactor constructs a redactor with safe defaults.
func NewRedactor(opts ...RedactorOption) (*Redactor, error) {
	cfg := redactorOptions{
		mask:     secretDefaultMask,
		keys:     normalizeRedactionKeys(defaultRedactionKeys()),
		maxDepth: redactionDefaultMaxDepth,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateRedactorConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Redactor{opts: cfg}, nil
}

// WithRedactionMask sets the redaction mask.
func WithRedactionMask(mask string) RedactorOption {
	return func(cfg *redactorOptions) error {
		if strings.TrimSpace(mask) == "" {
			return ErrInvalidRedactorConfig
		}

		cfg.mask = mask

		return nil
	}
}

// WithRedactionKeys adds additional sensitive keys to redact.
//
// The provided keys are merged into the existing set of redaction keys,
// which by default is initialized by NewRedactor with a set of common
// sensitive field names. Keys are normalized via normalizeRedactionKey
// (for example, lowercased and trimmed), so matching is case-insensitive
// and ignores surrounding whitespace. Keys that normalize to an empty
// string are ignored.
//
// If all provided keys normalize to empty strings (e.g., all whitespace),
// this option returns ErrInvalidRedactorConfig, regardless of whether
// existing redaction keys are already configured.
func WithRedactionKeys(keys ...string) RedactorOption {
	return func(cfg *redactorOptions) error {
		if len(keys) == 0 {
			return ErrInvalidRedactorConfig
		}

		if cfg.keys == nil {
			cfg.keys = make(map[string]struct{})
		}

		addedCount := 0
		for _, key := range keys {
			value := normalizeRedactionKey(key)
			if value == "" {
				continue
			}

			cfg.keys[value] = struct{}{}
			addedCount++
		}

		if addedCount == 0 {
			return ErrInvalidRedactorConfig
		}

		return nil
	}
}

// WithRedactionDetector uses a detector to redact secrets inside string values.
func WithRedactionDetector(detector *SecretDetector) RedactorOption {
	return func(cfg *redactorOptions) error {
		if detector == nil {
			return ErrInvalidRedactorConfig
		}

		cfg.detector = detector

		return nil
	}
}

// WithRedactionMaxDepth sets the maximum recursion depth for nested values.
func WithRedactionMaxDepth(depth int) RedactorOption {
	return func(cfg *redactorOptions) error {
		if depth <= 0 {
			return ErrInvalidRedactorConfig
		}

		cfg.maxDepth = depth

		return nil
	}
}

// RedactString returns the redaction mask for non-empty input.
func (r *Redactor) RedactString(input string) string {
	if input == "" {
		return ""
	}

	return r.opts.mask
}

// RedactFields redacts sensitive keys from a map of fields.
func (r *Redactor) RedactFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}

	value, _ := r.redactValue(fields, 0, "")

	redactedFields, ok := value.(map[string]any)
	if !ok {
		// If the redacted value is not a map[string]any, fall back to the original fields.
		return fields
	}

	return redactedFields
}

func (r *Redactor) redactValue(value any, depth int, key string) (any, bool) {
	if depth > r.opts.maxDepth {
		return value, false
	}

	if key != "" && r.isSensitiveKey(key) {
		return r.maskValue(value), true
	}

	switch typed := value.(type) {
	case map[string]any:
		return r.redactMapAny(typed, depth+1), true
	case map[string]string:
		return r.redactMapString(typed, depth+1), true
	case []any:
		return r.redactSliceAny(typed, depth+1), true
	case []string:
		return r.redactSliceString(typed, depth+1), true
	case string:
		return r.redactStringValue(typed), true
	default:
		return value, false
	}
}

func (r *Redactor) redactMapAny(fields map[string]any, depth int) map[string]any {
	if fields == nil {
		return nil
	}

	redacted := make(map[string]any, len(fields))
	for key, value := range fields {
		next, _ := r.redactValue(value, depth, key)
		redacted[key] = next
	}

	return redacted
}

func (r *Redactor) redactMapString(fields map[string]string, depth int) map[string]string {
	if fields == nil {
		return nil
	}

	redacted := make(map[string]string, len(fields))
	for key, value := range fields {
		if r.isSensitiveKey(key) {
			redacted[key] = r.RedactString(value)

			continue
		}

		redactedValue, ok := r.redactValue(value, depth, key)
		if !ok {
			redacted[key] = value

			continue
		}

		if result, ok := redactedValue.(string); ok {
			redacted[key] = result
		} else {
			redacted[key] = r.RedactString(value)
		}
	}

	return redacted
}

func (r *Redactor) redactSliceAny(values []any, depth int) []any {
	if values == nil {
		return nil
	}

	redacted := make([]any, len(values))
	for index, value := range values {
		next, _ := r.redactValue(value, depth, "")
		redacted[index] = next
	}

	return redacted
}

func (r *Redactor) redactSliceString(values []string, _ int) []string {
	if values == nil {
		return nil
	}

	redacted := make([]string, len(values))
	for index, value := range values {
		redacted[index] = r.redactStringValue(value)
	}

	return redacted
}

func (r *Redactor) redactStringValue(value string) string {
	if r.opts.detector == nil {
		return value
	}

	redacted, _, err := r.opts.detector.Redact(value)
	if err != nil {
		// If the detector fails, treat this as a failure condition rather than
		// forcing full redaction. Return the original value unchanged.
		return value
	}

	return redacted
}

func (r *Redactor) isSensitiveKey(key string) bool {
	normalized := normalizeRedactionKey(key)
	if normalized == "" {
		return false
	}

	_, ok := r.opts.keys[normalized]

	return ok
}

func (r *Redactor) maskValue(value any) any {
	if value == nil {
		return r.opts.mask
	}

	if str, ok := value.(string); ok {
		return r.RedactString(str)
	}

	return r.opts.mask
}

func validateRedactorConfig(cfg redactorOptions) error {
	if strings.TrimSpace(cfg.mask) == "" || cfg.maxDepth <= 0 {
		return ErrInvalidRedactorConfig
	}

	if len(cfg.keys) == 0 {
		return ErrInvalidRedactorConfig
	}

	return nil
}

func normalizeRedactionKeys(keys []string) map[string]struct{} {
	result := make(map[string]struct{})

	for _, key := range keys {
		value := normalizeRedactionKey(key)
		if value == "" {
			continue
		}

		result[value] = struct{}{}
	}

	return result
}

func normalizeRedactionKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func defaultRedactionKeys() []string {
	return []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"token",
		"access_token",
		"refresh_token",
		"authorization",
		"api_key",
		"apikey",
		"private_key",
		"client_secret",
		"cookie",
		"set-cookie",
	}
}
