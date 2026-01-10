package sanitize

import (
	"strings"
	"unicode"
)

const (
	sqlDetectDefaultMaxLength = 4096
)

// SQLDetectOption configures the SQL injection detector.
type SQLDetectOption func(*sqlDetectOptions) error

type sqlDetectOptions struct {
	maxLength int
	patterns  []string
}

// SQLInjectionDetector checks inputs for SQL injection heuristics.
type SQLInjectionDetector struct {
	opts sqlDetectOptions
}

// NewSQLInjectionDetector constructs a detector with safe defaults.
func NewSQLInjectionDetector(opts ...SQLDetectOption) (*SQLInjectionDetector, error) {
	cfg := sqlDetectOptions{
		maxLength: sqlDetectDefaultMaxLength,
		patterns:  defaultSQLInjectionPatterns(),
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

	err := validateSQLDetectConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &SQLInjectionDetector{opts: cfg}, nil
}

// WithSQLDetectMaxLength sets the maximum input length for detection.
func WithSQLDetectMaxLength(maxLength int) SQLDetectOption {
	return func(cfg *sqlDetectOptions) error {
		if maxLength <= 0 {
			return ErrInvalidSQLConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithSQLDetectPatterns replaces the default detection patterns.
func WithSQLDetectPatterns(patterns ...string) SQLDetectOption {
	return func(cfg *sqlDetectOptions) error {
		if len(patterns) == 0 {
			return ErrInvalidSQLConfig
		}

		normalized := normalizeDetectPatterns(patterns)
		if len(normalized) == 0 {
			return ErrInvalidSQLConfig
		}

		cfg.patterns = normalized

		return nil
	}
}

// Detect returns ErrSQLInjectionDetected when a pattern matches.
func (d *SQLInjectionDetector) Detect(input string) error {
	if len(input) > d.opts.maxLength {
		return ErrSQLInputTooLong
	}

	normalized := " " + normalizeDetectInput(input)
	for _, pattern := range d.opts.patterns {
		if strings.Contains(normalized, pattern) {
			return ErrSQLInjectionDetected
		}
	}

	return nil
}

func validateSQLDetectConfig(cfg sqlDetectOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidSQLConfig
	}

	if len(cfg.patterns) == 0 {
		return ErrInvalidSQLConfig
	}

	for _, pattern := range cfg.patterns {
		if strings.TrimSpace(pattern) == "" {
			return ErrInvalidSQLConfig
		}
	}

	return nil
}

func normalizeDetectInput(input string) string {
	lower := strings.ToLower(input)

	var builder strings.Builder
	builder.Grow(len(lower))

	spacePending := false

	for _, ch := range lower {
		if unicode.IsSpace(ch) {
			spacePending = true

			continue
		}

		if spacePending {
			builder.WriteByte(' ')

			spacePending = false
		}

		builder.WriteRune(ch)
	}

	return builder.String()
}

func defaultSQLInjectionPatterns() []string {
	return []string{
		"--",
		"/*",
		"*/",
		";",
		"union select",
		"union all select",
		" or 1=1",
		" or 1 = 1",
		" or '1'='1'",
		" or '1' = '1'",
		" or \"1\"=\"1\"",
		" or \"1\" = \"1\"",
		" or true",
		" and 1=1",
		" and 1 = 1",
		" and true",
		"sleep(",
		"pg_sleep(",
		"benchmark(",
		"waitfor delay",
	}
}

func normalizeDetectPatterns(patterns []string) []string {
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		value := strings.TrimSpace(strings.ToLower(pattern))
		if value == "" {
			continue
		}

		normalized = append(normalized, value)
	}

	return normalized
}
