package sanitize

import (
	"fmt"
	"html"
	"strings"

	nethtml "golang.org/x/net/html"
)

const (
	htmlDefaultMaxLength = 100_000
)

// HTMLSanitizeMode describes how HTML is sanitized.
type HTMLSanitizeMode int

const (
	// HTMLSanitizeEscape escapes HTML tags and entities.
	HTMLSanitizeEscape HTMLSanitizeMode = iota
	// HTMLSanitizeStrip removes HTML tags and returns plain text.
	HTMLSanitizeStrip
)

// HTMLPolicy defines a custom HTML sanitizer.
type HTMLPolicy interface {
	Sanitize(input string) (string, error)
}

// HTMLPolicyFunc adapts a function to HTMLPolicy.
type HTMLPolicyFunc func(input string) (string, error)

// Sanitize implements HTMLPolicy.
func (fn HTMLPolicyFunc) Sanitize(input string) (string, error) {
	return fn(input)
}

// HTMLOption configures the HTML sanitizer.
type HTMLOption func(*htmlOptions) error

type htmlOptions struct {
	maxLength int
	mode      HTMLSanitizeMode
	policy    HTMLPolicy
}

// HTMLSanitizer sanitizes HTML input with safe defaults.
type HTMLSanitizer struct {
	opts htmlOptions
}

// NewHTMLSanitizer constructs an HTML sanitizer with options.
func NewHTMLSanitizer(opts ...HTMLOption) (*HTMLSanitizer, error) {
	cfg := htmlOptions{
		maxLength: htmlDefaultMaxLength,
		mode:      HTMLSanitizeEscape,
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

	err := validateHTMLConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &HTMLSanitizer{opts: cfg}, nil
}

// WithHTMLMode sets the HTML sanitization mode.
func WithHTMLMode(mode HTMLSanitizeMode) HTMLOption {
	return func(cfg *htmlOptions) error {
		cfg.mode = mode

		return nil
	}
}

// WithHTMLMaxLength sets the maximum accepted HTML input length.
func WithHTMLMaxLength(maxLength int) HTMLOption {
	return func(cfg *htmlOptions) error {
		if maxLength <= 0 {
			return ErrInvalidHTMLConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithHTMLPolicy sets a custom HTML policy.
func WithHTMLPolicy(policy HTMLPolicy) HTMLOption {
	return func(cfg *htmlOptions) error {
		if policy == nil {
			return ErrInvalidHTMLConfig
		}

		cfg.policy = policy

		return nil
	}
}

// Sanitize sanitizes HTML content and returns a safe string.
func (s *HTMLSanitizer) Sanitize(input string) (string, error) {
	if len(input) > s.opts.maxLength {
		return "", ErrHTMLTooLong
	}

	if s.opts.policy != nil {
		return s.opts.policy.Sanitize(input)
	}

	switch s.opts.mode {
	case HTMLSanitizeEscape:
		return html.EscapeString(input), nil
	case HTMLSanitizeStrip:
		return stripHTML(input)
	default:
		return "", ErrInvalidHTMLConfig
	}
}

func validateHTMLConfig(cfg htmlOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidHTMLConfig
	}

	if cfg.mode != HTMLSanitizeEscape && cfg.mode != HTMLSanitizeStrip {
		return ErrInvalidHTMLConfig
	}

	return nil
}

func stripHTML(input string) (string, error) {
	doc, err := nethtml.Parse(strings.NewReader(input))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrHTMLInvalid, err)
	}

	var builder strings.Builder
	appendHTMLText(&builder, doc)

	return builder.String(), nil
}

func appendHTMLText(builder *strings.Builder, node *nethtml.Node) {
	if node == nil {
		return
	}

	if node.Type == nethtml.ElementNode && isStripElement(node.Data) {
		return
	}

	if node.Type == nethtml.TextNode {
		builder.WriteString(node.Data)
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		appendHTMLText(builder, child)
	}
}

func isStripElement(tag string) bool {
	switch tag {
	case "script", "style":
		return true
	default:
		return false
	}
}
