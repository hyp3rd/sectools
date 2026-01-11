package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	filenameDefaultMaxLength   = 255
	filenameDefaultReplacement = '_'
	filenameDeleteRune         = 0x7f
)

// FilenameOption configures filename sanitization.
type FilenameOption func(*filenameOptions) error

type filenameOptions struct {
	maxLength       int
	allowSpaces     bool
	allowUnicode    bool
	allowLeadingDot bool
	replacement     rune
}

// FilenameSanitizer sanitizes a single filename or path segment.
type FilenameSanitizer struct {
	opts filenameOptions
}

// NewFilenameSanitizer constructs a filename sanitizer with options.
func NewFilenameSanitizer(opts ...FilenameOption) (*FilenameSanitizer, error) {
	cfg := filenameOptions{
		maxLength:   filenameDefaultMaxLength,
		replacement: filenameDefaultReplacement,
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

	err := validateFilenameConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &FilenameSanitizer{opts: cfg}, nil
}

// WithFilenameMaxLength sets the maximum accepted filename length.
func WithFilenameMaxLength(maxLength int) FilenameOption {
	return func(cfg *filenameOptions) error {
		if maxLength <= 0 {
			return ErrInvalidFilenameConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithFilenameAllowSpaces allows spaces in filenames.
func WithFilenameAllowSpaces(allow bool) FilenameOption {
	return func(cfg *filenameOptions) error {
		cfg.allowSpaces = allow

		return nil
	}
}

// WithFilenameAllowUnicode allows Unicode characters in filenames.
func WithFilenameAllowUnicode(allow bool) FilenameOption {
	return func(cfg *filenameOptions) error {
		cfg.allowUnicode = allow

		return nil
	}
}

// WithFilenameAllowLeadingDot allows filenames starting with a dot.
func WithFilenameAllowLeadingDot(allow bool) FilenameOption {
	return func(cfg *filenameOptions) error {
		cfg.allowLeadingDot = allow

		return nil
	}
}

// WithFilenameReplacement sets the replacement rune for invalid characters.
func WithFilenameReplacement(replacement rune) FilenameOption {
	return func(cfg *filenameOptions) error {
		if !isValidReplacement(replacement) {
			return ErrInvalidFilenameConfig
		}

		cfg.replacement = replacement

		return nil
	}
}

// Sanitize normalizes a filename or path segment.
func (s *FilenameSanitizer) Sanitize(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", ErrFilenameEmpty
	}

	if len(value) > s.opts.maxLength {
		return "", ErrFilenameTooLong
	}

	var builder strings.Builder
	builder.Grow(len(value))

	for _, ch := range value {
		if isAllowedFilenameRune(ch, s.opts, builder.Len() == 0) {
			builder.WriteRune(ch)

			continue
		}

		builder.WriteRune(s.opts.replacement)
	}

	result := builder.String()
	if len(result) > s.opts.maxLength {
		return "", ErrFilenameTooLong
	}

	if result == "." || result == ".." {
		return "", ErrFilenameInvalid
	}

	if strings.HasSuffix(result, ".") || strings.HasSuffix(result, " ") {
		return "", ErrFilenameInvalid
	}

	return result, nil
}

func validateFilenameConfig(cfg filenameOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidFilenameConfig
	}

	if !isValidReplacement(cfg.replacement) {
		return ErrInvalidFilenameConfig
	}

	return nil
}

func isValidReplacement(replacement rune) bool {
	if replacement == '.' || unicode.IsSpace(replacement) {
		return false
	}

	return isAllowedFilenameRune(replacement, filenameOptions{allowUnicode: false, allowSpaces: false}, false)
}

func isAllowedFilenameRune(ch rune, cfg filenameOptions, isStart bool) bool {
	if !cfg.allowUnicode && ch >= utf8.RuneSelf {
		return false
	}

	if ch == 0 || ch == utf8.RuneError {
		return false
	}

	if ch < ' ' || ch == filenameDeleteRune {
		return false
	}

	if !cfg.allowSpaces && unicode.IsSpace(ch) {
		return false
	}

	if !cfg.allowLeadingDot && isStart && ch == '.' {
		return false
	}

	switch ch {
	case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
		return false
	default:
		return true
	}
}
