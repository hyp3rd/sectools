package encoding

import (
	"strings"
	"unicode"
)

func containsWhitespace(value string) bool {
	return strings.IndexFunc(value, unicode.IsSpace) >= 0
}
