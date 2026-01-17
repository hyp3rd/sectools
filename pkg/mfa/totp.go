package mfa

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"github.com/hyp3rd/sectools/pkg/converters"
)

// TOTP generates and verifies time-based one-time passwords.
// Instances of TOTP contain immutable configuration and can be used concurrently.
type TOTP struct {
	secret string
	opts   totpConfig
}

// TOTPOption configures TOTP verification behavior.
type TOTPOption func(*totpConfig) error

type totpConfig struct {
	digits         Digits
	algorithm      Algorithm
	period         time.Duration
	skew           uint
	minSecretBytes int
	clock          func() time.Time
	rateLimiter    RateLimiter
}

// NewTOTP constructs a TOTP helper using the provided base32 secret.
func NewTOTP(secret string, opts ...TOTPOption) (*TOTP, error) {
	cfg := defaultTOTPConfig()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateTOTPConfig(cfg)
	if err != nil {
		return nil, err
	}

	normalized, err := normalizeSecret(secret, cfg.minSecretBytes)
	if err != nil {
		return nil, err
	}

	return &TOTP{
		secret: normalized,
		opts:   cfg,
	}, nil
}

// Generate returns the current TOTP code using the configured clock.
func (t *TOTP) Generate() (string, error) {
	return t.generateAt(t.opts.clock())
}

// Verify checks whether the supplied TOTP code is valid for the current time.
func (t *TOTP) Verify(code string) (bool, error) {
	ok, _, err := t.verifyAtWithStep(code, t.opts.clock())

	return ok, err
}

// VerifyWithStep checks a TOTP code and returns the matched time step.
// Use the returned step to prevent replays by rejecting codes <= the last accepted step.
func (t *TOTP) VerifyWithStep(code string) (bool, uint64, error) {
	return t.verifyAtWithStep(code, t.opts.clock())
}

func (t *TOTP) generateAt(now time.Time) (string, error) {
	opts, err := t.validateOpts()
	if err != nil {
		return "", err
	}

	code, err := totp.GenerateCodeCustom(t.secret, now, opts)
	if err != nil {
		return "", fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return code, nil
}

func (t *TOTP) verifyAtWithStep(code string, now time.Time) (bool, uint64, error) {
	err := checkRateLimiter(t.opts.rateLimiter)
	if err != nil {
		return false, 0, err
	}

	normalized, err := normalizeCode(code, t.opts.digits)
	if err != nil {
		return false, 0, err
	}

	opts, err := t.validateOpts()
	if err != nil {
		return false, 0, err
	}

	baseCounter, ok, err := t.baseCounter(now)
	if err != nil {
		return false, 0, err
	}

	if !ok {
		return false, 0, nil
	}

	return t.verifyWithSkew(normalized, baseCounter, opts)
}

func (t *TOTP) baseCounter(now time.Time) (int64, bool, error) {
	stepSeconds := int64(t.opts.period / time.Second)
	if stepSeconds <= 0 {
		return 0, false, ErrInvalidMFAConfig
	}

	baseCounter := now.Unix() / stepSeconds
	if baseCounter < 0 {
		return 0, false, nil
	}

	return baseCounter, true, nil
}

func (t *TOTP) verifyWithSkew(normalized string, baseCounter int64, opts totp.ValidateOpts) (bool, uint64, error) {
	hotpOpts := hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	}

	ok, step, err := t.verifyAtCounter(normalized, baseCounter, hotpOpts)
	if err != nil || ok {
		return ok, step, err
	}

	for offset := uint(1); offset <= opts.Skew; offset++ {
		offsetValue, err := converters.SafeInt64FromUint64(uint64(offset))
		if err != nil {
			return false, 0, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
		}

		ok, step, err = t.verifyAtCounter(normalized, baseCounter+offsetValue, hotpOpts)
		if err != nil || ok {
			return ok, step, err
		}

		ok, step, err = t.verifyAtCounter(normalized, baseCounter-offsetValue, hotpOpts)
		if err != nil || ok {
			return ok, step, err
		}
	}

	return false, 0, nil
}

func (t *TOTP) verifyAtCounter(normalized string, counter int64, opts hotp.ValidateOpts) (bool, uint64, error) {
	if counter < 0 {
		return false, 0, nil
	}

	codeCandidate, err := hotp.GenerateCodeCustom(t.secret, uint64(counter), opts)
	if err != nil {
		return false, 0, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	if constantTimeEquals(normalized, codeCandidate) {
		return true, uint64(counter), nil
	}

	return false, 0, nil
}

func (t *TOTP) validateOpts() (totp.ValidateOpts, error) {
	periodSeconds, err := converters.SafeUintFromInt64(int64(t.opts.period / time.Second))
	if err != nil {
		return totp.ValidateOpts{}, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return totp.ValidateOpts{
		Period:    periodSeconds,
		Skew:      t.opts.skew,
		Digits:    t.opts.digits,
		Algorithm: t.opts.algorithm,
	}, nil
}

// WithTOTPDigits sets the number of digits for TOTP codes.
func WithTOTPDigits(digits Digits) TOTPOption {
	return func(cfg *totpConfig) error {
		if !isValidDigits(digits) {
			return ErrInvalidMFAConfig
		}

		cfg.digits = digits

		return nil
	}
}

// WithTOTPAlgorithm sets the HMAC algorithm for TOTP codes.
func WithTOTPAlgorithm(algorithm Algorithm) TOTPOption {
	return func(cfg *totpConfig) error {
		if !isValidAlgorithm(algorithm) {
			return ErrInvalidMFAConfig
		}

		cfg.algorithm = algorithm

		return nil
	}
}

// WithTOTPPeriod sets the TOTP period.
func WithTOTPPeriod(period time.Duration) TOTPOption {
	return func(cfg *totpConfig) error {
		if !isValidTOTPPeriod(period) {
			return ErrInvalidMFAConfig
		}

		cfg.period = period

		return nil
	}
}

// WithTOTPAllowedSkew sets the number of adjacent time steps allowed.
func WithTOTPAllowedSkew(skew uint) TOTPOption {
	return func(cfg *totpConfig) error {
		if skew > totpMaxSkew {
			return ErrInvalidMFAConfig
		}

		cfg.skew = skew

		return nil
	}
}

// WithTOTPSecretMinBytes sets the minimum secret length in bytes.
func WithTOTPSecretMinBytes(minBytes int) TOTPOption {
	return func(cfg *totpConfig) error {
		if minBytes < mfaAbsoluteMinSecret || minBytes > mfaMaxSecret {
			return ErrInvalidMFAConfig
		}

		cfg.minSecretBytes = minBytes

		return nil
	}
}

// WithTOTPClock sets the clock used for code generation and verification.
func WithTOTPClock(clock func() time.Time) TOTPOption {
	return func(cfg *totpConfig) error {
		if clock == nil {
			return ErrInvalidMFAConfig
		}

		cfg.clock = clock

		return nil
	}
}

// WithTOTPRateLimiter sets a rate limiter for TOTP verification.
func WithTOTPRateLimiter(limiter RateLimiter) TOTPOption {
	return func(cfg *totpConfig) error {
		if limiter == nil {
			return ErrInvalidMFAConfig
		}

		cfg.rateLimiter = limiter

		return nil
	}
}

func defaultTOTPConfig() totpConfig {
	return totpConfig{
		digits:         DigitsSix,
		algorithm:      AlgorithmSHA1,
		period:         totpDefaultPeriod,
		skew:           totpDefaultSkew,
		minSecretBytes: mfaDefaultMinSecret,
		clock:          time.Now,
	}
}

func validateTOTPConfig(cfg totpConfig) error {
	if !isValidDigits(cfg.digits) || !isValidAlgorithm(cfg.algorithm) {
		return ErrInvalidMFAConfig
	}

	if !isValidTOTPPeriod(cfg.period) {
		return ErrInvalidMFAConfig
	}

	if cfg.skew > totpMaxSkew {
		return ErrInvalidMFAConfig
	}

	if cfg.minSecretBytes < mfaAbsoluteMinSecret || cfg.minSecretBytes > mfaMaxSecret {
		return ErrInvalidMFAConfig
	}

	if cfg.clock == nil {
		return ErrInvalidMFAConfig
	}

	return nil
}

func isValidTOTPPeriod(period time.Duration) bool {
	if period < totpMinPeriod || period > totpMaxPeriod {
		return false
	}

	return period%time.Second == zeroDuration
}

// TOTPKeyOption configures provisioning for a new TOTP key.
type TOTPKeyOption func(*totpKeyConfig) error

type totpKeyConfig struct {
	issuer     string
	account    string
	digits     Digits
	algorithm  Algorithm
	period     time.Duration
	secretSize int
}

// GenerateTOTPKey creates a new provisioning key with a randomized secret.
func GenerateTOTPKey(opts ...TOTPKeyOption) (*otp.Key, error) {
	cfg := defaultTOTPKeyConfig()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateTOTPKeyConfig(cfg)
	if err != nil {
		return nil, err
	}

	periodSeconds, err := converters.SafeUintFromInt64(int64(cfg.period / time.Second))
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	secretSize, err := converters.ToUint(cfg.secretSize)
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.issuer,
		AccountName: cfg.account,
		Period:      periodSeconds,
		SecretSize:  secretSize,
		Digits:      cfg.digits,
		Algorithm:   cfg.algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return key, nil
}

// WithTOTPKeyIssuer sets the issuer for provisioning.
func WithTOTPKeyIssuer(issuer string) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		trimmed := strings.TrimSpace(issuer)
		if trimmed == "" {
			return ErrMFAMissingIssuer
		}

		cfg.issuer = trimmed

		return nil
	}
}

// WithTOTPKeyAccountName sets the account name for provisioning.
func WithTOTPKeyAccountName(account string) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		trimmed := strings.TrimSpace(account)
		if trimmed == "" {
			return ErrMFAMissingAccountName
		}

		cfg.account = trimmed

		return nil
	}
}

// WithTOTPKeyDigits sets the number of digits for provisioning.
func WithTOTPKeyDigits(digits Digits) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		if !isValidDigits(digits) {
			return ErrInvalidMFAConfig
		}

		cfg.digits = digits

		return nil
	}
}

// WithTOTPKeyAlgorithm sets the HMAC algorithm for provisioning.
func WithTOTPKeyAlgorithm(algorithm Algorithm) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		if !isValidAlgorithm(algorithm) {
			return ErrInvalidMFAConfig
		}

		cfg.algorithm = algorithm

		return nil
	}
}

// WithTOTPKeyPeriod sets the period for provisioning.
func WithTOTPKeyPeriod(period time.Duration) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		if !isValidTOTPPeriod(period) {
			return ErrInvalidMFAConfig
		}

		cfg.period = period

		return nil
	}
}

// WithTOTPKeySecretSize sets the secret size in bytes for provisioning.
func WithTOTPKeySecretSize(secretSize int) TOTPKeyOption {
	return func(cfg *totpKeyConfig) error {
		if secretSize < mfaAbsoluteMinSecret || secretSize > mfaMaxSecret {
			return ErrInvalidMFAConfig
		}

		cfg.secretSize = secretSize

		return nil
	}
}

func defaultTOTPKeyConfig() totpKeyConfig {
	return totpKeyConfig{
		digits:     DigitsSix,
		algorithm:  AlgorithmSHA1,
		period:     totpDefaultPeriod,
		secretSize: mfaDefaultSecretSize,
	}
}

func validateTOTPKeyConfig(cfg totpKeyConfig) error {
	if strings.TrimSpace(cfg.issuer) == "" {
		return ErrMFAMissingIssuer
	}

	if strings.TrimSpace(cfg.account) == "" {
		return ErrMFAMissingAccountName
	}

	if !isValidDigits(cfg.digits) || !isValidAlgorithm(cfg.algorithm) {
		return ErrInvalidMFAConfig
	}

	if !isValidTOTPPeriod(cfg.period) {
		return ErrInvalidMFAConfig
	}

	if cfg.secretSize < mfaAbsoluteMinSecret || cfg.secretSize > mfaMaxSecret {
		return ErrInvalidMFAConfig
	}

	return nil
}
