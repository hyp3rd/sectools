package sanitize

import "strings"

const (
	nosqlDetectDefaultMaxLength = 4096
)

// NoSQLDetectOption configures the NoSQL injection detector.
type NoSQLDetectOption func(*nosqlDetectOptions) error

type nosqlDetectOptions struct {
	maxLength int
	operators map[string]struct{}
}

// NoSQLInjectionDetector checks inputs for NoSQL injection heuristics.
type NoSQLInjectionDetector struct {
	opts nosqlDetectOptions
}

// NewNoSQLInjectionDetector constructs a detector with safe defaults.
func NewNoSQLInjectionDetector(opts ...NoSQLDetectOption) (*NoSQLInjectionDetector, error) {
	cfg := nosqlDetectOptions{
		maxLength: nosqlDetectDefaultMaxLength,
		operators: normalizeNoSQLOperators(defaultNoSQLOperators()),
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

	err := validateNoSQLDetectConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &NoSQLInjectionDetector{opts: cfg}, nil
}

// WithNoSQLDetectMaxLength sets the maximum input length for detection.
func WithNoSQLDetectMaxLength(maxLength int) NoSQLDetectOption {
	return func(cfg *nosqlDetectOptions) error {
		if maxLength <= 0 {
			return ErrInvalidNoSQLConfig
		}

		cfg.maxLength = maxLength

		return nil
	}
}

// WithNoSQLDetectOperators replaces the default operator list.
func WithNoSQLDetectOperators(operators ...string) NoSQLDetectOption {
	return func(cfg *nosqlDetectOptions) error {
		if len(operators) == 0 {
			return ErrInvalidNoSQLConfig
		}

		normalized := normalizeNoSQLOperators(operators)
		if len(normalized) == 0 {
			return ErrInvalidNoSQLConfig
		}

		cfg.operators = normalized

		return nil
	}
}

// Detect returns ErrNoSQLInjectionDetected when a pattern matches.
func (d *NoSQLInjectionDetector) Detect(input string) error {
	if len(input) > d.opts.maxLength {
		return ErrNoSQLInputTooLong
	}

	for index := 0; index < len(input); index++ {
		if input[index] != '$' {
			continue
		}

		if !isNoSQLOperatorBoundary(input, index) {
			continue
		}

		operator, end := readNoSQLOperator(input, index+1)
		if operator == "" {
			continue
		}

		if _, ok := d.opts.operators[operator]; ok {
			return ErrNoSQLInjectionDetected
		}

		if end > index {
			index = end - 1
		}
	}

	return nil
}

func validateNoSQLDetectConfig(cfg nosqlDetectOptions) error {
	if cfg.maxLength <= 0 {
		return ErrInvalidNoSQLConfig
	}

	if len(cfg.operators) == 0 {
		return ErrInvalidNoSQLConfig
	}

	return nil
}

func normalizeNoSQLOperators(operators []string) map[string]struct{} {
	normalized := make(map[string]struct{})

	for _, operator := range operators {
		value := strings.TrimSpace(strings.ToLower(strings.TrimPrefix(operator, "$")))
		if value == "" || !isASCIIAlphaString(value) {
			continue
		}

		normalized[value] = struct{}{}
	}

	return normalized
}

func isNoSQLOperatorBoundary(input string, index int) bool {
	if index == 0 {
		return true
	}

	prev := input[index-1]
	if prev <= ' ' {
		return true
	}

	switch prev {
	case '{', '[', ',', ':', '"', '\'', '(':
		return true
	default:
		return false
	}
}

func readNoSQLOperator(input string, start int) (string, int) {
	if start >= len(input) {
		return "", start
	}

	end := start
	for end < len(input) && isASCIIAlpha(input[end]) {
		end++
	}

	if end == start {
		return "", start
	}

	return strings.ToLower(input[start:end]), end
}

func isASCIIAlphaString(value string) bool {
	for index := range len(value) {
		if !isASCIIAlpha(value[index]) {
			return false
		}
	}

	return true
}

func defaultNoSQLOperators() []string {
	return []string{
		"ne",
		"eq",
		"gt",
		"gte",
		"lt",
		"lte",
		"in",
		"nin",
		"regex",
		"exists",
		"where",
		"expr",
		"or",
		"and",
		"nor",
		"not",
		"elemmatch",
		"size",
		"all",
		"text",
		"search",
		"function",
	}
}
