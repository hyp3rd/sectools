package secrets

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	secretDefaultMaxLength = 1 << 20
	secretDefaultMask      = "[REDACTED]"
)

// SecretPattern defines a named regex pattern for secret detection.
type SecretPattern struct {
	Name    string
	Pattern string
}

type secretCompiled struct {
	name string
	re   *regexp.Regexp
}

// SecretMatch describes a detected secret match.
type SecretMatch struct {
	Pattern string
	Value   string
	Start   int
	End     int
}

// SecretDetectOption configures SecretDetector.
type SecretDetectOption func(*secretOptions) error

type secretOptions struct {
	maxLength int
	mask      string
	patterns  []SecretPattern
}

// SecretDetector detects secrets in text and can redact them.
type SecretDetector struct {
	opts     secretOptions
	patterns []secretCompiled
}

// NewSecretDetector constructs a detector with safe defaults.
func NewSecretDetector(opts ...SecretDetectOption) (*SecretDetector, error) {
	cfg := secretOptions{
		maxLength: secretDefaultMaxLength,
		mask:      secretDefaultMask,
		patterns:  defaultSecretPatterns(),
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

	patterns, err := compileSecretPatterns(cfg)
	if err != nil {
		return nil, err
	}

	return &SecretDetector{
		opts:     cfg,
		patterns: patterns,
	}, nil
}

// WithSecretPatterns replaces the default detection patterns.
func WithSecretPatterns(patterns ...SecretPattern) SecretDetectOption {
	return func(cfg *secretOptions) error {
		if len(patterns) == 0 {
			return ErrInvalidSecretConfig
		}

		cfg.patterns = patterns

		return nil
	}
}

// WithSecretPattern adds a detection pattern.
func WithSecretPattern(name, pattern string) SecretDetectOption {
	return func(cfg *secretOptions) error {
		cfg.patterns = append(cfg.patterns, SecretPattern{Name: name, Pattern: pattern})

		return nil
	}
}

// WithSecretMaxLength sets the maximum input length for detection.
func WithSecretMaxLength(maxLength int) SecretDetectOption {
	return func(cfg *secretOptions) error {
		if maxLength <= 0 {
			return ErrInvalidSecretConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithSecretMask sets the redaction mask.
func WithSecretMask(mask string) SecretDetectOption {
	return func(cfg *secretOptions) error {
		if strings.TrimSpace(mask) == "" {
			return ErrInvalidSecretConfig
		}

		cfg.mask = mask

		return nil
	}
}

// Detect scans input and returns all matches.
func (d *SecretDetector) Detect(input string) ([]SecretMatch, error) {
	if len(input) > d.opts.maxLength {
		return nil, ErrSecretInputTooLong
	}

	if strings.TrimSpace(input) == "" {
		return nil, nil
	}

	matches := make([]SecretMatch, 0)

	for _, pattern := range d.patterns {
		indexes := pattern.re.FindAllStringIndex(input, -1)
		for _, index := range indexes {
			if len(index) != 2 {
				continue
			}

			start := index[0]

			end := index[1]
			if start < 0 || end <= start || end > len(input) {
				continue
			}

			matches = append(matches, SecretMatch{
				Pattern: pattern.name,
				Value:   input[start:end],
				Start:   start,
				End:     end,
			})
		}
	}

	return matches, nil
}

// DetectAny returns ErrSecretDetected when a secret is found.
func (d *SecretDetector) DetectAny(input string) error {
	matches, err := d.Detect(input)
	if err != nil {
		return err
	}

	if len(matches) > 0 {
		return ErrSecretDetected
	}

	return nil
}

// Redact replaces detected secrets with the configured mask.
func (d *SecretDetector) Redact(input string) (string, []SecretMatch, error) {
	matches, err := d.Detect(input)
	if err != nil {
		return "", nil, err
	}

	if len(matches) == 0 {
		return input, nil, nil
	}

	return redactMatches(input, matches, d.opts.mask), matches, nil
}

func redactMatches(input string, matches []SecretMatch, mask string) string {
	ranges := mergeSecretRanges(matches)
	if len(ranges) == 0 {
		return input
	}

	var builder strings.Builder
	builder.Grow(len(input))

	cursor := 0
	for _, match := range ranges {
		if match.Start > cursor {
			builder.WriteString(input[cursor:match.Start])
		}

		builder.WriteString(mask)

		cursor = match.End
	}

	if cursor < len(input) {
		builder.WriteString(input[cursor:])
	}

	return builder.String()
}

func mergeSecretRanges(matches []SecretMatch) []SecretMatch {
	if len(matches) == 0 {
		return nil
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start == matches[j].Start {
			return matches[i].End < matches[j].End
		}

		return matches[i].Start < matches[j].Start
	})

	merged := make([]SecretMatch, 0, len(matches))
	for _, match := range matches {
		if match.Start < 0 || match.End <= match.Start {
			continue
		}

		if len(merged) == 0 {
			merged = append(merged, match)

			continue
		}

		last := &merged[len(merged)-1]
		if match.Start <= last.End {
			if match.End > last.End {
				last.End = match.End
			}

			continue
		}

		merged = append(merged, match)
	}

	return merged
}

func compileSecretPatterns(cfg secretOptions) ([]secretCompiled, error) {
	if cfg.maxLength <= 0 || strings.TrimSpace(cfg.mask) == "" {
		return nil, ErrInvalidSecretConfig
	}

	if len(cfg.patterns) == 0 {
		return nil, ErrInvalidSecretConfig
	}

	compiled := make([]secretCompiled, 0, len(cfg.patterns))
	for _, pattern := range cfg.patterns {
		if strings.TrimSpace(pattern.Name) == "" || strings.TrimSpace(pattern.Pattern) == "" {
			return nil, ErrInvalidSecretConfig
		}

		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSecretConfig, err)
		}

		compiled = append(compiled, secretCompiled{
			name: pattern.Name,
			re:   re,
		})
	}

	return compiled, nil
}

func defaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{Name: "aws-access-key", Pattern: `AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}`},
		{Name: "github-token", Pattern: `gh[pousr]_[A-Za-z0-9]{36,}`},
		{Name: "slack-token", Pattern: `xox[baprs]-[A-Za-z0-9-]{10,}`},
		{Name: "google-api-key", Pattern: `AIza[0-9A-Za-z_-]{35}`},
		{Name: "stripe-secret", Pattern: `sk_live_[0-9a-zA-Z]{24,}`},
		{Name: "jwt", Pattern: `eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`},
		{Name: "private-key", Pattern: `-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`},
		{Name: "bearer-token", Pattern: `(?i)bearer\s+[a-z0-9._-]{16,}`},
	}
}
