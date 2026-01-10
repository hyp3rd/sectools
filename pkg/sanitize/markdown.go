package sanitize

import "html"

const (
	markdownDefaultMaxLength = 100_000
)

// MarkdownOption configures the Markdown sanitizer.
type MarkdownOption func(*markdownOptions) error

type markdownOptions struct {
	maxLength    int
	allowRawHTML bool
}

// MarkdownSanitizer sanitizes Markdown input with safe defaults.
type MarkdownSanitizer struct {
	opts markdownOptions
}

// NewMarkdownSanitizer constructs a Markdown sanitizer with options.
func NewMarkdownSanitizer(opts ...MarkdownOption) (*MarkdownSanitizer, error) {
	cfg := markdownOptions{
		maxLength: markdownDefaultMaxLength,
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

	err := validateMarkdownConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &MarkdownSanitizer{opts: cfg}, nil
}

// WithMarkdownMaxLength sets the maximum accepted Markdown input length.
func WithMarkdownMaxLength(maxLength int) MarkdownOption {
	return func(cfg *markdownOptions) error {
		if maxLength <= 0 {
			return ErrInvalidMarkdownConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithMarkdownAllowRawHTML allows raw HTML inside Markdown.
func WithMarkdownAllowRawHTML(allow bool) MarkdownOption {
	return func(cfg *markdownOptions) error {
		cfg.allowRawHTML = allow

		return nil
	}
}

// Sanitize sanitizes Markdown input and returns a safe string.
func (s *MarkdownSanitizer) Sanitize(input string) (string, error) {
	if len(input) > s.opts.maxLength {
		return "", ErrMarkdownTooLong
	}

	if s.opts.allowRawHTML {
		return input, nil
	}

	return html.EscapeString(input), nil
}

func validateMarkdownConfig(cfg markdownOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidMarkdownConfig
	}

	return nil
}
