package mfa

import (
	"fmt"
	"math"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"

	"github.com/hyp3rd/sectools/pkg/converters"
)

// HOTP generates and verifies counter-based one-time passwords.
// Instances of HOTP contain immutable configuration and can be used concurrently.
type HOTP struct {
	secret string
	opts   hotpConfig
}

// HOTPOption configures HOTP verification behavior.
type HOTPOption func(*hotpConfig) error

type hotpConfig struct {
	digits         Digits
	algorithm      Algorithm
	lookAhead      uint
	minSecretBytes int
}

// NewHOTP constructs an HOTP helper using the provided base32 secret.
func NewHOTP(secret string, opts ...HOTPOption) (*HOTP, error) {
	cfg := defaultHOTPConfig()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateHOTPConfig(cfg)
	if err != nil {
		return nil, err
	}

	normalized, err := normalizeSecret(secret, cfg.minSecretBytes)
	if err != nil {
		return nil, err
	}

	return &HOTP{
		secret: normalized,
		opts:   cfg,
	}, nil
}

// Generate returns the HOTP code for the specified counter.
func (h *HOTP) Generate(counter uint64) (string, error) {
	code, err := hotp.GenerateCodeCustom(h.secret, counter, h.validateOpts())
	if err != nil {
		return "", fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return code, nil
}

// Verify checks whether the supplied HOTP code is valid for the counter window.
// On success, it returns true and the next counter to persist.
func (h *HOTP) Verify(code string, counter uint64) (bool, uint64, error) {
	normalized, err := normalizeCode(code, h.opts.digits)
	if err != nil {
		return false, counter, err
	}

	maxOffset := uint64(h.opts.lookAhead)
	for offset := zeroUint64; offset <= maxOffset; offset++ {
		if counter > math.MaxUint64-offset {
			return false, counter, ErrMFAInvalidCounter
		}

		candidate, err := hotp.GenerateCodeCustom(h.secret, counter+offset, h.validateOpts())
		if err != nil {
			return false, counter, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
		}

		if constantTimeEquals(normalized, candidate) {
			return true, counter + offset + counterIncrement, nil
		}
	}

	return false, counter, nil
}

func (h *HOTP) validateOpts() hotp.ValidateOpts {
	return hotp.ValidateOpts{
		Digits:    h.opts.digits,
		Algorithm: h.opts.algorithm,
	}
}

// WithHOTPDigits sets the number of digits for HOTP codes.
func WithHOTPDigits(digits Digits) HOTPOption {
	return func(cfg *hotpConfig) error {
		if !isValidDigits(digits) {
			return ErrInvalidMFAConfig
		}

		cfg.digits = digits

		return nil
	}
}

// WithHOTPAlgorithm sets the HMAC algorithm for HOTP codes.
func WithHOTPAlgorithm(algorithm Algorithm) HOTPOption {
	return func(cfg *hotpConfig) error {
		if !isValidAlgorithm(algorithm) {
			return ErrInvalidMFAConfig
		}

		cfg.algorithm = algorithm

		return nil
	}
}

// WithHOTPWindow sets the look-ahead counter window.
func WithHOTPWindow(lookAhead uint) HOTPOption {
	return func(cfg *hotpConfig) error {
		if lookAhead > hotpMaxLookAhead {
			return ErrInvalidMFAConfig
		}

		cfg.lookAhead = lookAhead

		return nil
	}
}

// WithHOTPSecretMinBytes sets the minimum secret length in bytes.
func WithHOTPSecretMinBytes(minBytes int) HOTPOption {
	return func(cfg *hotpConfig) error {
		if minBytes < mfaAbsoluteMinSecret || minBytes > mfaMaxSecret {
			return ErrInvalidMFAConfig
		}

		cfg.minSecretBytes = minBytes

		return nil
	}
}

func defaultHOTPConfig() hotpConfig {
	return hotpConfig{
		digits:         DigitsSix,
		algorithm:      AlgorithmSHA1,
		lookAhead:      hotpDefaultLookAhead,
		minSecretBytes: mfaDefaultMinSecret,
	}
}

func validateHOTPConfig(cfg hotpConfig) error {
	if !isValidDigits(cfg.digits) || !isValidAlgorithm(cfg.algorithm) {
		return ErrInvalidMFAConfig
	}

	if cfg.lookAhead > hotpMaxLookAhead {
		return ErrInvalidMFAConfig
	}

	if cfg.minSecretBytes < mfaAbsoluteMinSecret || cfg.minSecretBytes > mfaMaxSecret {
		return ErrInvalidMFAConfig
	}

	return nil
}

// HOTPKeyOption configures provisioning for a new HOTP key.
type HOTPKeyOption func(*hotpKeyConfig) error

type hotpKeyConfig struct {
	issuer     string
	account    string
	digits     Digits
	algorithm  Algorithm
	secretSize int
}

// GenerateHOTPKey creates a new provisioning key with a randomized secret.
func GenerateHOTPKey(opts ...HOTPKeyOption) (*otp.Key, error) {
	cfg := defaultHOTPKeyConfig()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateHOTPKeyConfig(cfg)
	if err != nil {
		return nil, err
	}

	secretSize, err := converters.ToUint(cfg.secretSize)
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	key, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      cfg.issuer,
		AccountName: cfg.account,
		SecretSize:  secretSize,
		Digits:      cfg.digits,
		Algorithm:   cfg.algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return key, nil
}

// WithHOTPKeyIssuer sets the issuer for provisioning.
func WithHOTPKeyIssuer(issuer string) HOTPKeyOption {
	return func(cfg *hotpKeyConfig) error {
		trimmed := strings.TrimSpace(issuer)
		if trimmed == "" {
			return ErrMFAMissingIssuer
		}

		cfg.issuer = trimmed

		return nil
	}
}

// WithHOTPKeyAccountName sets the account name for provisioning.
func WithHOTPKeyAccountName(account string) HOTPKeyOption {
	return func(cfg *hotpKeyConfig) error {
		trimmed := strings.TrimSpace(account)
		if trimmed == "" {
			return ErrMFAMissingAccountName
		}

		cfg.account = trimmed

		return nil
	}
}

// WithHOTPKeyDigits sets the number of digits for provisioning.
func WithHOTPKeyDigits(digits Digits) HOTPKeyOption {
	return func(cfg *hotpKeyConfig) error {
		if !isValidDigits(digits) {
			return ErrInvalidMFAConfig
		}

		cfg.digits = digits

		return nil
	}
}

// WithHOTPKeyAlgorithm sets the HMAC algorithm for provisioning.
func WithHOTPKeyAlgorithm(algorithm Algorithm) HOTPKeyOption {
	return func(cfg *hotpKeyConfig) error {
		if !isValidAlgorithm(algorithm) {
			return ErrInvalidMFAConfig
		}

		cfg.algorithm = algorithm

		return nil
	}
}

// WithHOTPKeySecretSize sets the secret size in bytes for provisioning.
func WithHOTPKeySecretSize(secretSize int) HOTPKeyOption {
	return func(cfg *hotpKeyConfig) error {
		if secretSize < mfaAbsoluteMinSecret || secretSize > mfaMaxSecret {
			return ErrInvalidMFAConfig
		}

		cfg.secretSize = secretSize

		return nil
	}
}

func defaultHOTPKeyConfig() hotpKeyConfig {
	return hotpKeyConfig{
		digits:     DigitsSix,
		algorithm:  AlgorithmSHA1,
		secretSize: mfaDefaultSecretSize,
	}
}

func validateHOTPKeyConfig(cfg hotpKeyConfig) error {
	if strings.TrimSpace(cfg.issuer) == "" {
		return ErrMFAMissingIssuer
	}

	if strings.TrimSpace(cfg.account) == "" {
		return ErrMFAMissingAccountName
	}

	if !isValidDigits(cfg.digits) || !isValidAlgorithm(cfg.algorithm) {
		return ErrInvalidMFAConfig
	}

	if cfg.secretSize < mfaAbsoluteMinSecret || cfg.secretSize > mfaMaxSecret {
		return ErrInvalidMFAConfig
	}

	return nil
}
