package sanitize

import (
	"strings"
	"unicode/utf8"
)

const (
	sqlDefaultIdentifierMaxLength = 128
	sqlDefaultLiteralMaxLength    = 4096
	sqlDefaultLikeMaxLength       = 4096
	sqlDefaultLikeEscape          = '\\'
)

// SQLMode describes the SQL sanitization strategy.
type SQLMode int

const (
	// SQLModeIdentifier sanitizes SQL identifiers (table/column names).
	SQLModeIdentifier SQLMode = iota
	// SQLModeLiteral sanitizes SQL literals for safe embedding in string literals.
	SQLModeLiteral
	// SQLModeLikePattern sanitizes SQL LIKE patterns with escaping.
	SQLModeLikePattern
)

// SQLOption configures the SQL sanitizer.
type SQLOption func(*sqlOptions) error

type sqlOptions struct {
	mode           SQLMode
	maxLength      int
	allowQualified bool
	likeEscape     rune
}

// SQLSanitizer sanitizes SQL inputs with safe defaults.
type SQLSanitizer struct {
	opts sqlOptions
}

// NewSQLSanitizer constructs a SQL sanitizer with options.
func NewSQLSanitizer(opts ...SQLOption) (*SQLSanitizer, error) {
	cfg := sqlOptions{
		mode:       SQLModeIdentifier,
		likeEscape: sqlDefaultLikeEscape,
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

	if cfg.maxLength == 0 {
		cfg.maxLength = sqlDefaultMaxLength(cfg.mode)
	}

	err := validateSQLConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &SQLSanitizer{opts: cfg}, nil
}

// WithSQLMode sets the SQL sanitization mode.
func WithSQLMode(mode SQLMode) SQLOption {
	return func(cfg *sqlOptions) error {
		cfg.mode = mode

		return nil
	}
}

// WithSQLMaxLength sets the maximum accepted SQL input length.
func WithSQLMaxLength(maxLength int) SQLOption {
	return func(cfg *sqlOptions) error {
		if maxLength <= 0 {
			return ErrInvalidSQLConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithSQLAllowQualifiedIdentifiers allows dotted identifiers (schema.table).
func WithSQLAllowQualifiedIdentifiers(allow bool) SQLOption {
	return func(cfg *sqlOptions) error {
		cfg.allowQualified = allow

		return nil
	}
}

// WithSQLLikeEscapeChar sets the escape character for SQL LIKE patterns.
func WithSQLLikeEscapeChar(ch rune) SQLOption {
	return func(cfg *sqlOptions) error {
		cfg.likeEscape = ch

		return nil
	}
}

// Sanitize sanitizes SQL input for the configured mode.
func (s *SQLSanitizer) Sanitize(input string) (string, error) {
	if len(input) > s.opts.maxLength {
		return "", ErrSQLInputTooLong
	}

	switch s.opts.mode {
	case SQLModeIdentifier:
		return s.sanitizeIdentifier(input)
	case SQLModeLiteral:
		return sanitizeSQLLiteral(input)
	case SQLModeLikePattern:
		return s.sanitizeLikePattern(input)
	default:
		return "", ErrInvalidSQLConfig
	}
}

func validateSQLConfig(cfg sqlOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidSQLConfig
	}

	if cfg.mode != SQLModeIdentifier && cfg.mode != SQLModeLiteral && cfg.mode != SQLModeLikePattern {
		return ErrInvalidSQLConfig
	}

	if cfg.allowQualified && cfg.mode != SQLModeIdentifier {
		return ErrInvalidSQLConfig
	}

	if cfg.mode == SQLModeLikePattern && !isValidLikeEscape(cfg.likeEscape) {
		return ErrSQLLikeEscapeInvalid
	}

	return nil
}

func (s *SQLSanitizer) sanitizeIdentifier(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", ErrSQLIdentifierInvalid
	}

	if s.opts.allowQualified {
		return sanitizeQualifiedIdentifier(value)
	}

	err := validateIdentifierSegment(value)
	if err != nil {
		return "", err
	}

	return value, nil
}

func sanitizeQualifiedIdentifier(value string) (string, error) {
	parts := strings.SplitSeq(value, ".")
	for part := range parts {
		err := validateIdentifierSegment(part)
		if err != nil {
			return "", err
		}
	}

	return value, nil
}

func validateIdentifierSegment(segment string) error {
	if segment == "" {
		return ErrSQLIdentifierInvalid
	}

	for index := range len(segment) {
		ch := segment[index]
		if ch >= utf8.RuneSelf {
			return ErrSQLIdentifierInvalid
		}

		if index == 0 {
			if !isIdentifierStart(ch) {
				return ErrSQLIdentifierInvalid
			}

			continue
		}

		if !isIdentifierPart(ch) {
			return ErrSQLIdentifierInvalid
		}
	}

	return nil
}

func isIdentifierStart(ch byte) bool {
	if ch == '_' {
		return true
	}

	return isASCIIAlpha(ch)
}

func isIdentifierPart(ch byte) bool {
	return isIdentifierStart(ch) || isASCIIDigit(ch)
}

func isASCIIAlpha(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
}

func isASCIIDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func sanitizeSQLLiteral(input string) (string, error) {
	if strings.ContainsRune(input, 0) {
		return "", ErrSQLLiteralInvalid
	}

	return strings.ReplaceAll(input, "'", "''"), nil
}

func (s *SQLSanitizer) sanitizeLikePattern(input string) (string, error) {
	if strings.ContainsRune(input, 0) {
		return "", ErrSQLLiteralInvalid
	}

	return escapeLikePattern(input, s.opts.likeEscape)
}

func escapeLikePattern(input string, escape rune) (string, error) {
	if !isValidLikeEscape(escape) {
		return "", ErrSQLLikeEscapeInvalid
	}

	var builder strings.Builder
	builder.Grow(len(input))

	for _, ch := range input {
		switch ch {
		case '\'':
			builder.WriteString("''")

			continue
		case '%', '_':
			builder.WriteRune(escape)
		default:
			if ch == escape {
				builder.WriteRune(escape)
			}
		}

		builder.WriteRune(ch)
	}

	return builder.String(), nil
}

func isValidLikeEscape(ch rune) bool {
	if ch == 0 {
		return false
	}

	if ch == '\'' || ch == '%' || ch == '_' {
		return false
	}

	return ch < utf8.RuneSelf
}

func sqlDefaultMaxLength(mode SQLMode) int {
	if mode == SQLModeIdentifier {
		return sqlDefaultIdentifierMaxLength
	}

	if mode == SQLModeLikePattern {
		return sqlDefaultLikeMaxLength
	}

	return sqlDefaultLiteralMaxLength
}
