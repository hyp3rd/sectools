package auth

import (
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

const pasetoWrapFormat = "%w: %w"

// PasetoLocal encrypts and decrypts PASETO v4 local tokens.
type PasetoLocal struct {
	key               paseto.V4SymmetricKey
	requireExpiration bool
	issuer            string
	audience          string
	subject           string
	clock             func() time.Time
}

// PasetoLocalOption configures PASETO local behavior.
type PasetoLocalOption func(*pasetoLocalConfig) error

type pasetoLocalConfig struct {
	key               paseto.V4SymmetricKey
	hasKey            bool
	requireExpiration bool
	issuer            string
	audience          string
	subject           string
	clock             func() time.Time
}

// NewPasetoLocal constructs a PASETO v4 local helper.
func NewPasetoLocal(opts ...PasetoLocalOption) (*PasetoLocal, error) {
	cfg := pasetoLocalConfig{
		requireExpiration: true,
		clock:             time.Now,
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

	if !cfg.hasKey {
		return nil, ErrPasetoMissingKey
	}

	if cfg.clock == nil {
		return nil, ErrPasetoInvalidConfig
	}

	return &PasetoLocal{
		key:               cfg.key,
		requireExpiration: cfg.requireExpiration,
		issuer:            cfg.issuer,
		audience:          cfg.audience,
		subject:           cfg.subject,
		clock:             cfg.clock,
	}, nil
}

// WithPasetoLocalKey sets the symmetric key.
func WithPasetoLocalKey(key paseto.V4SymmetricKey) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		cfg.key = key
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoLocalKeyBytes sets the symmetric key from raw bytes.
func WithPasetoLocalKeyBytes(key []byte) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		if len(key) == 0 {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.V4SymmetricKeyFromBytes(key)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoLocalKeyHex sets the symmetric key from a hex string.
func WithPasetoLocalKeyHex(hexKey string) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		trimmed := strings.TrimSpace(hexKey)
		if trimmed == "" {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.V4SymmetricKeyFromHex(trimmed)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoLocalIssuer sets the expected issuer.
func WithPasetoLocalIssuer(issuer string) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		cfg.issuer = strings.TrimSpace(issuer)

		return nil
	}
}

// WithPasetoLocalAudience sets the expected audience.
func WithPasetoLocalAudience(audience string) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		cfg.audience = strings.TrimSpace(audience)

		return nil
	}
}

// WithPasetoLocalSubject sets the expected subject.
func WithPasetoLocalSubject(subject string) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		cfg.subject = strings.TrimSpace(subject)

		return nil
	}
}

// WithPasetoLocalClock overrides the clock used for validation.
func WithPasetoLocalClock(clock func() time.Time) PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		if clock == nil {
			return ErrPasetoInvalidConfig
		}

		cfg.clock = clock

		return nil
	}
}

// WithPasetoLocalAllowMissingExpiration disables the default requirement for exp.
func WithPasetoLocalAllowMissingExpiration() PasetoLocalOption {
	return func(cfg *pasetoLocalConfig) error {
		cfg.requireExpiration = false

		return nil
	}
}

// Encrypt encrypts a token using v4 local.
func (p *PasetoLocal) Encrypt(token *paseto.Token) (string, error) {
	if token == nil {
		return "", ErrPasetoMissingToken
	}

	if p.requireExpiration && !pasetoTokenHasExpiration(token) {
		return "", ErrPasetoMissingExpiry
	}

	return token.V4Encrypt(p.key, nil), nil
}

// Decrypt decrypts and validates a v4 local token.
func (p *PasetoLocal) Decrypt(tokenString string) (*paseto.Token, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, ErrPasetoMissingToken
	}

	parser := newPasetoParser(p.requireExpiration, p.issuer, p.audience, p.subject, p.clock())

	token, err := parser.ParseV4Local(p.key, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidToken, err)
	}

	return token, nil
}

// PasetoPublicSigner signs PASETO v4 public tokens.
type PasetoPublicSigner struct {
	key               paseto.V4AsymmetricSecretKey
	requireExpiration bool
}

// PasetoPublicSignerOption configures PASETO public signing behavior.
type PasetoPublicSignerOption func(*pasetoPublicSignerConfig) error

type pasetoPublicSignerConfig struct {
	key               paseto.V4AsymmetricSecretKey
	hasKey            bool
	requireExpiration bool
}

// NewPasetoPublicSigner constructs a PASETO v4 public signer.
func NewPasetoPublicSigner(opts ...PasetoPublicSignerOption) (*PasetoPublicSigner, error) {
	cfg := pasetoPublicSignerConfig{
		requireExpiration: true,
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

	if !cfg.hasKey {
		return nil, ErrPasetoMissingKey
	}

	return &PasetoPublicSigner{
		key:               cfg.key,
		requireExpiration: cfg.requireExpiration,
	}, nil
}

// WithPasetoPublicSecretKey sets the asymmetric secret key.
func WithPasetoPublicSecretKey(key paseto.V4AsymmetricSecretKey) PasetoPublicSignerOption {
	return func(cfg *pasetoPublicSignerConfig) error {
		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		cfg.key = key
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicSecretKeyBytes sets the asymmetric secret key from bytes.
func WithPasetoPublicSecretKeyBytes(key []byte) PasetoPublicSignerOption {
	return func(cfg *pasetoPublicSignerConfig) error {
		if len(key) == 0 {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.NewV4AsymmetricSecretKeyFromBytes(key)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicSecretKeyHex sets the asymmetric secret key from hex.
func WithPasetoPublicSecretKeyHex(hexKey string) PasetoPublicSignerOption {
	return func(cfg *pasetoPublicSignerConfig) error {
		trimmed := strings.TrimSpace(hexKey)
		if trimmed == "" {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.NewV4AsymmetricSecretKeyFromHex(trimmed)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicSignerAllowMissingExpiration disables the default requirement for exp.
func WithPasetoPublicSignerAllowMissingExpiration() PasetoPublicSignerOption {
	return func(cfg *pasetoPublicSignerConfig) error {
		cfg.requireExpiration = false

		return nil
	}
}

// Sign signs a token using v4 public.
func (p *PasetoPublicSigner) Sign(token *paseto.Token) (string, error) {
	if token == nil {
		return "", ErrPasetoMissingToken
	}

	if p.requireExpiration && !pasetoTokenHasExpiration(token) {
		return "", ErrPasetoMissingExpiry
	}

	return token.V4Sign(p.key, nil), nil
}

// PasetoPublicVerifier verifies PASETO v4 public tokens.
type PasetoPublicVerifier struct {
	key               paseto.V4AsymmetricPublicKey
	requireExpiration bool
	issuer            string
	audience          string
	subject           string
	clock             func() time.Time
}

// PasetoPublicVerifierOption configures PASETO public verification behavior.
type PasetoPublicVerifierOption func(*pasetoPublicVerifierConfig) error

type pasetoPublicVerifierConfig struct {
	key               paseto.V4AsymmetricPublicKey
	hasKey            bool
	requireExpiration bool
	issuer            string
	audience          string
	subject           string
	clock             func() time.Time
}

// NewPasetoPublicVerifier constructs a PASETO v4 public verifier.
func NewPasetoPublicVerifier(opts ...PasetoPublicVerifierOption) (*PasetoPublicVerifier, error) {
	cfg := pasetoPublicVerifierConfig{
		requireExpiration: true,
		clock:             time.Now,
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

	if !cfg.hasKey {
		return nil, ErrPasetoMissingKey
	}

	if cfg.clock == nil {
		return nil, ErrPasetoInvalidConfig
	}

	return &PasetoPublicVerifier{
		key:               cfg.key,
		requireExpiration: cfg.requireExpiration,
		issuer:            cfg.issuer,
		audience:          cfg.audience,
		subject:           cfg.subject,
		clock:             cfg.clock,
	}, nil
}

// WithPasetoPublicKey sets the asymmetric public key.
func WithPasetoPublicKey(key paseto.V4AsymmetricPublicKey) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		cfg.key = key
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicKeyBytes sets the asymmetric public key from bytes.
func WithPasetoPublicKeyBytes(key []byte) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		if len(key) == 0 {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.NewV4AsymmetricPublicKeyFromBytes(key)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicKeyHex sets the asymmetric public key from hex.
func WithPasetoPublicKeyHex(hexKey string) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		trimmed := strings.TrimSpace(hexKey)
		if trimmed == "" {
			return ErrPasetoMissingKey
		}

		if cfg.hasKey {
			return ErrPasetoConflictingOpts
		}

		parsed, err := paseto.NewV4AsymmetricPublicKeyFromHex(trimmed)
		if err != nil {
			return fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidConfig, err)
		}

		cfg.key = parsed
		cfg.hasKey = true

		return nil
	}
}

// WithPasetoPublicIssuer sets the expected issuer.
func WithPasetoPublicIssuer(issuer string) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		cfg.issuer = strings.TrimSpace(issuer)

		return nil
	}
}

// WithPasetoPublicAudience sets the expected audience.
func WithPasetoPublicAudience(audience string) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		cfg.audience = strings.TrimSpace(audience)

		return nil
	}
}

// WithPasetoPublicSubject sets the expected subject.
func WithPasetoPublicSubject(subject string) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		cfg.subject = strings.TrimSpace(subject)

		return nil
	}
}

// WithPasetoPublicClock overrides the clock used for validation.
func WithPasetoPublicClock(clock func() time.Time) PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		if clock == nil {
			return ErrPasetoInvalidConfig
		}

		cfg.clock = clock

		return nil
	}
}

// WithPasetoPublicAllowMissingExpiration disables the default requirement for exp.
func WithPasetoPublicAllowMissingExpiration() PasetoPublicVerifierOption {
	return func(cfg *pasetoPublicVerifierConfig) error {
		cfg.requireExpiration = false

		return nil
	}
}

// Verify verifies and parses a v4 public token.
func (p *PasetoPublicVerifier) Verify(tokenString string) (*paseto.Token, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, ErrPasetoMissingToken
	}

	parser := newPasetoParser(p.requireExpiration, p.issuer, p.audience, p.subject, p.clock())

	token, err := parser.ParseV4Public(p.key, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf(pasetoWrapFormat, ErrPasetoInvalidToken, err)
	}

	return token, nil
}

func newPasetoParser(requireExpiration bool, issuer, audience, subject string, now time.Time) paseto.Parser {
	parser := paseto.NewParserWithoutExpiryCheck()

	if requireExpiration {
		parser.AddRule(pasetoExpiryRule(now))
	}

	if issuer != "" {
		parser.AddRule(paseto.IssuedBy(issuer))
	}

	if audience != "" {
		parser.AddRule(paseto.ForAudience(audience))
	}

	if subject != "" {
		parser.AddRule(paseto.Subject(subject))
	}

	return parser
}

func pasetoExpiryRule(now time.Time) paseto.Rule {
	return func(token paseto.Token) error {
		expiration, err := token.GetExpiration()
		if err != nil {
			return ErrPasetoMissingExpiry
		}

		if now.After(expiration) {
			return ErrPasetoExpired
		}

		return nil
	}
}

func pasetoTokenHasExpiration(token *paseto.Token) bool {
	expiration, err := token.GetExpiration()
	if err != nil || expiration.IsZero() {
		return false
	}

	return true
}
