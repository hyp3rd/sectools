package mfa

import (
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"time"
)

const (
	totpDefaultPeriod                    = 30 * time.Second
	totpMinPeriod                        = 15 * time.Second
	totpMaxPeriod                        = 5 * time.Minute
	totpDefaultSkew                      = 1
	totpMaxSkew                          = 3
	hotpDefaultLookAhead                 = 3
	hotpMaxLookAhead                     = 10
	mfaDefaultSecretSize                 = 20
	mfaDefaultMinSecret                  = 16
	mfaAbsoluteMinSecret                 = 10
	mfaMaxSecret                         = 64
	digitsSixLength                      = 6
	digitsEightLength                    = 8
	secretPaddingCharacter               = "="
	mfaWrapFormat                        = "%w: %w"
	digitsInvalidLength    int           = 0
	zeroDuration           time.Duration = 0
	zeroUint64             uint64        = 0
	counterIncrement       uint64        = 1
	constantTimeMatch      int           = 1
)

func isValidDigits(digits Digits) bool {
	return digits == DigitsSix || digits == DigitsEight
}

func isValidAlgorithm(alg Algorithm) bool {
	switch alg {
	case AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512:
		return true
	default:
		return false
	}
}

func digitsLength(digits Digits) int {
	switch digits {
	case DigitsSix:
		return digitsSixLength
	case DigitsEight:
		return digitsEightLength
	default:
		return digitsInvalidLength
	}
}

func normalizeCode(code string, digits Digits) (string, error) {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return "", ErrMFAInvalidCode
	}

	if len(trimmed) != digitsLength(digits) {
		return "", ErrMFAInvalidCode
	}

	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return "", ErrMFAInvalidCode
		}
	}

	return trimmed, nil
}

func normalizeSecret(secret string, minBytes int) (string, error) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return "", ErrMFAInvalidSecret
	}

	if minBytes < mfaAbsoluteMinSecret || minBytes > mfaMaxSecret {
		return "", ErrInvalidMFAConfig
	}

	normalized := strings.ToUpper(trimmed)
	normalized = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-':
			return -1
		default:
			return r
		}
	}, normalized)
	normalized = strings.TrimRight(normalized, secretPaddingCharacter)

	if normalized == "" {
		return "", ErrMFAInvalidSecret
	}

	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)

	decodedLen := decoder.DecodedLen(len(normalized))
	if decodedLen > mfaMaxSecret {
		return "", ErrMFASecretTooLong
	}

	decoded, err := decoder.DecodeString(normalized)
	if err != nil {
		return "", ErrMFAInvalidSecret
	}

	if len(decoded) < minBytes {
		return "", ErrMFASecretTooShort
	}

	if len(decoded) > mfaMaxSecret {
		return "", ErrMFASecretTooLong
	}

	return normalized, nil
}

func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == constantTimeMatch
}
