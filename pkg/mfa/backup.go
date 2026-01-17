package mfa

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/hyp3rd/ewrap"

	"github.com/hyp3rd/sectools/pkg/password"
)

const (
	backupDefaultCount             = 10
	backupMinCount                 = 1
	backupMaxCount                 = 20
	backupDefaultLength            = 12
	backupMinLength                = 8
	backupMaxLength                = 32
	backupDefaultGroupSize         = 4
	backupGroupDisabled            = 0
	backupMinAlphabetSize          = 16
	backupGenerationAttemptsPerKey = 10
	backupGroupSeparator           = "-"
	backupDefaultAlphabet          = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // cspell:disable-line
	byteRange                      = 256
)

// BackupHasher hashes and verifies backup codes for storage.
type BackupHasher interface {
	Hash(code []byte) (string, error)
	Verify(code []byte, hash string) (bool, error)
}

type argon2idBackupHasher struct {
	hasher *password.Argon2idHasher
}

func (h argon2idBackupHasher) Hash(code []byte) (string, error) {
	return h.hasher.Hash(code)
}

func (h argon2idBackupHasher) Verify(code []byte, hash string) (bool, error) {
	ok, _, err := h.hasher.Verify(code, hash)

	return ok, err
}

type bcryptBackupHasher struct {
	hasher *password.BcryptHasher
}

func (h bcryptBackupHasher) Hash(code []byte) (string, error) {
	return h.hasher.Hash(code)
}

func (h bcryptBackupHasher) Verify(code []byte, hash string) (bool, error) {
	ok, _, err := h.hasher.Verify(code, hash)

	return ok, err
}

// BackupCodeSet contains the generated backup codes and their hashes.
type BackupCodeSet struct {
	Codes  []string
	Hashes []string
}

// BackupCodeManager generates and verifies recovery codes.
// Instances are immutable and safe for concurrent use.
type BackupCodeManager struct {
	cfg      backupConfig
	hasher   BackupHasher
	alphabet []byte
	allowed  [byteRange]bool
	reader   io.Reader
}

// BackupOption configures backup code generation and verification.
type BackupOption func(*backupConfig) error

type backupConfig struct {
	count       int
	length      int
	groupSize   int
	alphabet    string
	hasher      BackupHasher
	hasherSet   bool
	reader      io.Reader
	rateLimiter RateLimiter
}

// NewBackupCodeManager constructs a backup code manager with safe defaults.
func NewBackupCodeManager(opts ...BackupOption) (*BackupCodeManager, error) {
	cfg := defaultBackupConfig()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err := validateBackupConfig(&cfg)
	if err != nil {
		return nil, err
	}

	normalizedAlphabet, allowed, err := normalizeAlphabet(cfg.alphabet)
	if err != nil {
		return nil, err
	}

	hasher, err := resolveBackupHasher(&cfg)
	if err != nil {
		return nil, err
	}

	reader := cfg.reader
	if reader == nil {
		reader = rand.Reader
	}

	return &BackupCodeManager{
		cfg:      cfg,
		hasher:   hasher,
		alphabet: []byte(normalizedAlphabet),
		allowed:  allowed,
		reader:   reader,
	}, nil
}

// Generate produces a set of backup codes and hashes for storage.
func (m *BackupCodeManager) Generate() (BackupCodeSet, error) {
	target := m.cfg.count
	codes := make([]string, 0, target)
	hashes := make([]string, 0, target)
	seen := make(map[string]struct{}, target)

	maxAttempts := m.cfg.count * backupGenerationAttemptsPerKey
	attempts := 0

	for len(codes) < target {
		if attempts >= maxAttempts {
			return BackupCodeSet{}, ErrMFABackupGenerationFailed
		}

		raw, err := m.generateRawCode()
		if err != nil {
			return BackupCodeSet{}, fmt.Errorf(mfaWrapFormat, ErrMFABackupGenerationFailed, err)
		}

		attempts++

		if _, exists := seen[raw]; exists {
			continue
		}

		seen[raw] = struct{}{}

		hash, err := m.hasher.Hash([]byte(raw))
		if err != nil {
			return BackupCodeSet{}, fmt.Errorf(mfaWrapFormat, ErrMFABackupHashFailed, err)
		}

		codes = append(codes, formatBackupCode(raw, m.cfg.groupSize))
		hashes = append(hashes, hash)
	}

	return BackupCodeSet{Codes: codes, Hashes: hashes}, nil
}

// Verify checks a backup code and returns the remaining hashes if it matched.
func (m *BackupCodeManager) Verify(code string, hashes []string) (bool, []string, error) {
	err := checkRateLimiter(m.cfg.rateLimiter)
	if err != nil {
		return false, nil, err
	}

	normalized, err := m.normalizeBackupCode(code)
	if err != nil {
		return false, nil, err
	}

	remaining := make([]string, 0, len(hashes))

	for _, hash := range hashes {
		ok, err := m.hasher.Verify([]byte(normalized), hash)
		if err != nil {
			return false, nil, fmt.Errorf(mfaWrapFormat, ErrMFABackupVerificationFailed, err)
		}

		if ok {
			continue
		}

		remaining = append(remaining, hash)
	}

	if len(remaining) == len(hashes) {
		return false, remaining, nil
	}

	return true, remaining, nil
}

// WithBackupCodeCount sets the number of backup codes to generate.
func WithBackupCodeCount(count int) BackupOption {
	return func(cfg *backupConfig) error {
		if count < backupMinCount || count > backupMaxCount {
			return ErrInvalidMFAConfig
		}

		cfg.count = count

		return nil
	}
}

// WithBackupCodeLength sets the length of each backup code.
func WithBackupCodeLength(length int) BackupOption {
	return func(cfg *backupConfig) error {
		if length < backupMinLength || length > backupMaxLength {
			return ErrInvalidMFAConfig
		}

		cfg.length = length

		return nil
	}
}

// WithBackupCodeGroupSize sets the grouping size for formatting.
func WithBackupCodeGroupSize(size int) BackupOption {
	return func(cfg *backupConfig) error {
		if size < backupGroupDisabled {
			return ErrInvalidMFAConfig
		}

		cfg.groupSize = size

		return nil
	}
}

// WithBackupCodeAlphabet sets the alphabet used for backup code generation.
func WithBackupCodeAlphabet(alphabet string) BackupOption {
	return func(cfg *backupConfig) error {
		trimmed := strings.TrimSpace(alphabet)
		if trimmed == "" {
			return ErrInvalidMFAConfig
		}

		cfg.alphabet = trimmed

		return nil
	}
}

// WithBackupHasher sets a custom hasher for backup codes.
func WithBackupHasher(hasher BackupHasher) BackupOption {
	return func(cfg *backupConfig) error {
		if hasher == nil {
			return ErrInvalidMFAConfig
		}

		if cfg.hasherSet {
			return ErrMFAConflictingOptions
		}

		cfg.hasher = hasher
		cfg.hasherSet = true

		return nil
	}
}

// WithBackupHasherArgon2id configures Argon2id hashing for backup codes.
func WithBackupHasherArgon2id(params password.Argon2idParams) BackupOption {
	return func(cfg *backupConfig) error {
		if cfg.hasherSet {
			return ErrMFAConflictingOptions
		}

		hasher, err := password.NewArgon2id(params)
		if err != nil {
			return fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
		}

		cfg.hasher = argon2idBackupHasher{hasher: hasher}
		cfg.hasherSet = true

		return nil
	}
}

// WithBackupHasherBcrypt configures bcrypt hashing for backup codes.
func WithBackupHasherBcrypt(cost int) BackupOption {
	return func(cfg *backupConfig) error {
		if cfg.hasherSet {
			return ErrMFAConflictingOptions
		}

		hasher, err := password.NewBcrypt(cost)
		if err != nil {
			return fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
		}

		cfg.hasher = bcryptBackupHasher{hasher: hasher}
		cfg.hasherSet = true

		return nil
	}
}

// WithBackupCodeReader sets the randomness source for backup code generation.
func WithBackupCodeReader(reader io.Reader) BackupOption {
	return func(cfg *backupConfig) error {
		if reader == nil {
			return ErrInvalidMFAConfig
		}

		cfg.reader = reader

		return nil
	}
}

// WithBackupRateLimiter sets a rate limiter for backup code verification.
func WithBackupRateLimiter(limiter RateLimiter) BackupOption {
	return func(cfg *backupConfig) error {
		if limiter == nil {
			return ErrInvalidMFAConfig
		}

		cfg.rateLimiter = limiter

		return nil
	}
}

func defaultBackupConfig() backupConfig {
	return backupConfig{
		count:     backupDefaultCount,
		length:    backupDefaultLength,
		groupSize: backupDefaultGroupSize,
		alphabet:  backupDefaultAlphabet,
		reader:    rand.Reader,
	}
}

func validateBackupConfig(cfg *backupConfig) error {
	if cfg.count < backupMinCount || cfg.count > backupMaxCount {
		return ErrInvalidMFAConfig
	}

	if cfg.length < backupMinLength || cfg.length > backupMaxLength {
		return ErrInvalidMFAConfig
	}

	if cfg.groupSize < backupGroupDisabled || cfg.groupSize > cfg.length {
		return ErrInvalidMFAConfig
	}

	if strings.TrimSpace(cfg.alphabet) == "" {
		return ErrInvalidMFAConfig
	}

	if cfg.reader == nil {
		return ErrInvalidMFAConfig
	}

	return nil
}

func resolveBackupHasher(cfg *backupConfig) (BackupHasher, error) {
	if cfg.hasher != nil {
		return cfg.hasher, nil
	}

	hasher, err := password.NewArgon2id(password.Argon2idBalanced())
	if err != nil {
		return nil, fmt.Errorf(mfaWrapFormat, ErrInvalidMFAConfig, err)
	}

	return argon2idBackupHasher{hasher: hasher}, nil
}

func normalizeAlphabet(alphabet string) (string, [byteRange]bool, error) {
	var allowed [byteRange]bool

	normalized := strings.ToUpper(strings.TrimSpace(alphabet))
	if normalized == "" {
		return "", allowed, ErrInvalidMFAConfig
	}

	for i := range len(normalized) {
		ch := normalized[i]
		if ch < '0' || ch > 'Z' || (ch > '9' && ch < 'A') {
			return "", allowed, ErrInvalidMFAConfig
		}

		if allowed[ch] {
			return "", allowed, ErrInvalidMFAConfig
		}

		allowed[ch] = true
	}

	if len(normalized) < backupMinAlphabetSize {
		return "", allowed, ErrInvalidMFAConfig
	}

	return normalized, allowed, nil
}

func (m *BackupCodeManager) normalizeBackupCode(code string) (string, error) {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return "", ErrMFAInvalidCode
	}

	normalized := make([]byte, 0, len(trimmed))

	for i := range len(trimmed) {
		ch := trimmed[i]
		switch ch {
		case ' ', '-':
			continue
		default:
			// Continue normal validation for all other characters.
		}

		if ch >= 'a' && ch <= 'z' {
			ch -= ('a' - 'A')
		}

		if !m.allowed[ch] {
			return "", ErrMFAInvalidCode
		}

		normalized = append(normalized, ch)
	}

	if len(normalized) != m.cfg.length {
		return "", ErrMFAInvalidCode
	}

	return string(normalized), nil
}

func (m *BackupCodeManager) generateRawCode() (string, error) {
	output := make([]byte, m.cfg.length)

	alphabetSize := len(m.alphabet)
	if alphabetSize == 0 || alphabetSize > byteRange {
		return "", ErrInvalidMFAConfig
	}

	limit := byteRange - (byteRange % alphabetSize)

	for i := range output {
		for {
			var buf [1]byte

			_, err := io.ReadFull(m.reader, buf[:])
			if err != nil {
				return "", ewrap.Wrap(err, "failed to read random bytes for backup code")
			}

			if int(buf[0]) >= limit {
				continue
			}

			output[i] = m.alphabet[int(buf[0])%alphabetSize]

			break
		}
	}

	return string(output), nil
}

func formatBackupCode(code string, groupSize int) string {
	if groupSize <= backupGroupDisabled || groupSize >= len(code) {
		return code
	}

	separatorCount := len(code) / groupSize
	if len(code)%groupSize == 0 {
		separatorCount--
	}

	var builder strings.Builder
	builder.Grow(len(code) + separatorCount)

	for i := range len(code) {
		if i > 0 && i%groupSize == 0 {
			builder.WriteString(backupGroupSeparator)
		}

		builder.WriteByte(code[i])
	}

	return builder.String()
}
