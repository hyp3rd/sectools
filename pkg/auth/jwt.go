package auth

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const jwtHeaderKeyID = "kid"

// JWTSigner signs JWTs with required claims and strict algorithm selection.
type JWTSigner struct {
	method            jwt.SigningMethod
	key               any
	keyID             string
	requireExpiration bool
}

// JWTSignerOption configures JWT signing behavior.
type JWTSignerOption func(*jwtSignerConfig) error

type jwtSignerConfig struct {
	method            jwt.SigningMethod
	key               any
	keyID             string
	requireExpiration bool
}

// NewJWTSigner constructs a JWT signer with strict defaults.
func NewJWTSigner(opts ...JWTSignerOption) (*JWTSigner, error) {
	cfg := jwtSignerConfig{
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

	if cfg.method == nil {
		return nil, ErrJWTMissingSigningAlg
	}

	if cfg.key == nil {
		return nil, ErrJWTMissingKey
	}

	return &JWTSigner{
		method:            cfg.method,
		key:               cfg.key,
		keyID:             cfg.keyID,
		requireExpiration: cfg.requireExpiration,
	}, nil
}

// WithJWTSigningAlgorithm configures the signing algorithm by name.
func WithJWTSigningAlgorithm(alg string) JWTSignerOption {
	return func(cfg *jwtSignerConfig) error {
		trimmed := strings.TrimSpace(alg)
		if trimmed == "" {
			return ErrJWTMissingSigningAlg
		}

		if strings.EqualFold(trimmed, "none") {
			return ErrJWTInvalidConfig
		}

		method := jwt.GetSigningMethod(trimmed)
		if method == nil {
			return ErrJWTInvalidConfig
		}

		cfg.method = method

		return nil
	}
}

// WithJWTSigningKey sets the signing key.
func WithJWTSigningKey(key any) JWTSignerOption {
	return func(cfg *jwtSignerConfig) error {
		if key == nil {
			return ErrJWTMissingKey
		}

		cfg.key = key

		return nil
	}
}

// WithJWTSigningKeyID sets the kid header on signed tokens.
func WithJWTSigningKeyID(keyID string) JWTSignerOption {
	return func(cfg *jwtSignerConfig) error {
		cfg.keyID = strings.TrimSpace(keyID)

		return nil
	}
}

// WithJWTSignerAllowMissingExpiration disables the default requirement for exp.
func WithJWTSignerAllowMissingExpiration() JWTSignerOption {
	return func(cfg *jwtSignerConfig) error {
		cfg.requireExpiration = false

		return nil
	}
}

// Sign signs claims into a JWT string.
func (s *JWTSigner) Sign(claims jwt.Claims) (string, error) {
	if claims == nil {
		return "", ErrJWTMissingClaims
	}

	if s.requireExpiration {
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			return "", ErrJWTMissingExpiration
		}
	}

	token := jwt.NewWithClaims(s.method, claims)
	if s.keyID != "" {
		token.Header[jwtHeaderKeyID] = s.keyID
	}

	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signed, nil
}

// JWTVerifier verifies JWT signatures and claims with strict validation.
type JWTVerifier struct {
	allowedAlgs       []string
	key               any
	keys              map[string]any
	keyFunc           jwt.Keyfunc
	requireKeyID      bool
	issuer            string
	audiences         []string
	subject           string
	leeway            time.Duration
	now               func() time.Time
	requireExpiration bool
}

// JWTVerifierOption configures JWT verification behavior.
type JWTVerifierOption func(*jwtVerifierConfig) error

type jwtVerifierConfig struct {
	allowedAlgs       []string
	key               any
	keys              map[string]any
	keyFunc           jwt.Keyfunc
	requireKeyID      bool
	issuer            string
	audiences         []string
	subject           string
	leeway            time.Duration
	now               func() time.Time
	requireExpiration bool
}

// NewJWTVerifier constructs a JWT verifier with strict defaults.
func NewJWTVerifier(opts ...JWTVerifierOption) (*JWTVerifier, error) {
	cfg := jwtVerifierConfig{
		requireExpiration: true,
		now:               time.Now,
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

	err := validateJWTVerifierConfig(&cfg)
	if err != nil {
		return nil, err
	}

	return &JWTVerifier{
		allowedAlgs:       cfg.allowedAlgs,
		key:               cfg.key,
		keys:              cfg.keys,
		keyFunc:           cfg.keyFunc,
		requireKeyID:      cfg.requireKeyID,
		issuer:            cfg.issuer,
		audiences:         cfg.audiences,
		subject:           cfg.subject,
		leeway:            cfg.leeway,
		now:               cfg.now,
		requireExpiration: cfg.requireExpiration,
	}, nil
}

func validateJWTVerifierConfig(cfg *jwtVerifierConfig) error {
	if len(cfg.allowedAlgs) == 0 {
		return ErrJWTMissingAllowedAlgs
	}

	err := validateJWTKeySources(cfg)
	if err != nil {
		return err
	}

	err = validateJWTIssuerAudiences(cfg.issuer, cfg.audiences)
	if err != nil {
		return err
	}

	err = validateJWTClock(cfg.now, cfg.leeway)
	if err != nil {
		return err
	}

	return nil
}

func validateJWTKeySources(cfg *jwtVerifierConfig) error {
	keySources := 0
	if cfg.key != nil {
		keySources++
	}

	if len(cfg.keys) > 0 {
		keySources++
	}

	if cfg.keyFunc != nil {
		keySources++
	}

	if keySources == 0 {
		return ErrJWTMissingKey
	}

	if keySources > 1 {
		return ErrJWTConflictingOptions
	}

	return nil
}

func validateJWTIssuerAudiences(issuer string, audiences []string) error {
	if issuer == "" {
		return ErrJWTInvalidConfig
	}

	if len(audiences) == 0 {
		return ErrJWTInvalidConfig
	}

	for _, audience := range audiences {
		if strings.TrimSpace(audience) == "" {
			return ErrJWTInvalidConfig
		}
	}

	return nil
}

func validateJWTClock(now func() time.Time, leeway time.Duration) error {
	if now == nil {
		return ErrJWTInvalidConfig
	}

	if leeway < 0 {
		return ErrJWTInvalidConfig
	}

	return nil
}

// WithJWTAllowedAlgorithms configures allowed signing algorithms.
func WithJWTAllowedAlgorithms(algs ...string) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cleaned := make([]string, 0, len(algs))
		for _, alg := range algs {
			trimmed := strings.TrimSpace(alg)
			if trimmed == "" {
				continue
			}

			if strings.EqualFold(trimmed, "none") {
				return ErrJWTInvalidConfig
			}

			cleaned = append(cleaned, trimmed)
		}

		if len(cleaned) == 0 {
			return ErrJWTMissingAllowedAlgs
		}

		cfg.allowedAlgs = cleaned

		return nil
	}
}

// WithJWTVerificationKey configures a single verification key.
func WithJWTVerificationKey(key any) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		if key == nil {
			return ErrJWTMissingKey
		}

		cfg.key = key

		return nil
	}
}

// WithJWTVerificationKeys configures a key map by kid.
func WithJWTVerificationKeys(keys map[string]any) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		if len(keys) == 0 {
			return ErrJWTMissingKey
		}

		cfg.keys = make(map[string]any, len(keys))
		maps.Copy(cfg.keys, keys)

		cfg.requireKeyID = true

		return nil
	}
}

// WithJWTVerificationKeyFunc configures a custom key function.
func WithJWTVerificationKeyFunc(keyFunc jwt.Keyfunc) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		if keyFunc == nil {
			return ErrJWTMissingKey
		}

		cfg.keyFunc = keyFunc

		return nil
	}
}

// WithJWTRequireKeyID requires a kid header even with a single key.
func WithJWTRequireKeyID() JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cfg.requireKeyID = true

		return nil
	}
}

// WithJWTIssuer configures the required issuer.
func WithJWTIssuer(issuer string) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cfg.issuer = strings.TrimSpace(issuer)

		return nil
	}
}

// WithJWTAudience configures the required audience list.
func WithJWTAudience(audiences ...string) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cleaned := make([]string, 0, len(audiences))
		for _, audience := range audiences {
			trimmed := strings.TrimSpace(audience)
			if trimmed == "" {
				continue
			}

			cleaned = append(cleaned, trimmed)
		}

		cfg.audiences = cleaned

		return nil
	}
}

// WithJWTSubject configures the required subject.
func WithJWTSubject(subject string) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cfg.subject = strings.TrimSpace(subject)

		return nil
	}
}

// WithJWTLeeway configures allowable clock skew.
func WithJWTLeeway(leeway time.Duration) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cfg.leeway = leeway

		return nil
	}
}

// WithJWTClock overrides the clock used for validation.
func WithJWTClock(now func() time.Time) JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		if now == nil {
			return ErrJWTInvalidConfig
		}

		cfg.now = now

		return nil
	}
}

// WithJWTVerifierAllowMissingExpiration disables the default requirement for exp.
func WithJWTVerifierAllowMissingExpiration() JWTVerifierOption {
	return func(cfg *jwtVerifierConfig) error {
		cfg.requireExpiration = false

		return nil
	}
}

// Verify parses and validates a JWT into the provided claims.
func (v *JWTVerifier) Verify(tokenString string, claims jwt.Claims) error {
	if strings.TrimSpace(tokenString) == "" {
		return ErrJWTInvalidToken
	}

	if claims == nil {
		return ErrJWTMissingClaims
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(v.allowedAlgs),
		jwt.WithoutClaimsValidation(),
	)
	keyFunc := v.resolveKeyFunc()

	token, err := parser.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWTInvalidToken, err)
	}

	if token == nil || token.Method == nil {
		return ErrJWTInvalidToken
	}

	if !token.Valid {
		return ErrJWTInvalidToken
	}

	if !containsString(v.allowedAlgs, token.Method.Alg()) {
		return ErrJWTInvalidToken
	}

	return v.validateClaims(claims)
}

// VerifyMap parses and validates a JWT into a map of claims.
func (v *JWTVerifier) VerifyMap(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	err := v.Verify(tokenString, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (v *JWTVerifier) resolveKeyFunc() jwt.Keyfunc {
	if v.keyFunc != nil {
		return v.wrapKeyFunc(v.keyFunc)
	}

	if len(v.keys) > 0 {
		return v.keyMapFunc()
	}

	return v.singleKeyFunc()
}

func (v *JWTVerifier) wrapKeyFunc(keyFunc jwt.Keyfunc) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		_, err := v.tokenKeyID(token, v.requireKeyID)
		if err != nil {
			return nil, err
		}

		return keyFunc(token)
	}
}

func (v *JWTVerifier) keyMapFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, err := v.tokenKeyID(token, true)
		if err != nil {
			return nil, err
		}

		key, ok := v.keys[kid]
		if !ok || key == nil {
			return nil, ErrJWTMissingKey
		}

		return key, nil
	}
}

func (v *JWTVerifier) singleKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		_, err := v.tokenKeyID(token, v.requireKeyID)
		if err != nil {
			return nil, err
		}

		return v.key, nil
	}
}

func (*JWTVerifier) tokenKeyID(token *jwt.Token, required bool) (string, error) {
	value, ok := token.Header[jwtHeaderKeyID].(string)
	if !ok {
		if required {
			return "", ErrJWTMissingKeyID
		}

		return "", nil
	}

	kid := strings.TrimSpace(value)
	if kid == "" {
		if required {
			return "", ErrJWTMissingKeyID
		}

		return "", nil
	}

	return kid, nil
}

func (v *JWTVerifier) validateClaims(claims jwt.Claims) error {
	now := v.now()

	err := v.validateExpiration(claims, now)
	if err != nil {
		return err
	}

	err = v.validateNotBefore(claims, now)
	if err != nil {
		return err
	}

	err = v.validateIssuedAt(claims, now)
	if err != nil {
		return err
	}

	err = v.validateIssuer(claims)
	if err != nil {
		return err
	}

	err = v.validateSubject(claims)
	if err != nil {
		return err
	}

	return v.validateAudience(claims)
}

func (v *JWTVerifier) validateExpiration(claims jwt.Claims, now time.Time) error {
	if !v.requireExpiration {
		return nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return ErrJWTMissingExpiration
	}

	if now.After(exp.Add(v.leeway)) {
		return ErrJWTInvalidToken
	}

	return nil
}

func (v *JWTVerifier) validateNotBefore(claims jwt.Claims, now time.Time) error {
	nbf, err := claims.GetNotBefore()
	if err != nil {
		return ErrJWTInvalidToken
	}

	if nbf == nil {
		return nil
	}

	if now.Add(v.leeway).Before(nbf.Time) {
		return ErrJWTInvalidToken
	}

	return nil
}

func (v *JWTVerifier) validateIssuedAt(claims jwt.Claims, now time.Time) error {
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return ErrJWTInvalidToken
	}

	if iat == nil {
		return nil
	}

	if now.Add(v.leeway).Before(iat.Time) {
		return ErrJWTInvalidToken
	}

	return nil
}

func (v *JWTVerifier) validateIssuer(claims jwt.Claims) error {
	if v.issuer == "" {
		return nil
	}

	iss, err := claims.GetIssuer()
	if err != nil {
		return ErrJWTInvalidToken
	}

	iss = strings.TrimSpace(iss)
	if iss == "" {
		return ErrJWTMissingClaims
	}

	if iss != v.issuer {
		return ErrJWTInvalidToken
	}

	return nil
}

func (v *JWTVerifier) validateSubject(claims jwt.Claims) error {
	if v.subject == "" {
		return nil
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return ErrJWTInvalidToken
	}

	sub = strings.TrimSpace(sub)
	if sub == "" {
		return ErrJWTMissingClaims
	}

	if sub != v.subject {
		return ErrJWTInvalidToken
	}

	return nil
}

func (v *JWTVerifier) validateAudience(claims jwt.Claims) error {
	if len(v.audiences) == 0 {
		return nil
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return ErrJWTInvalidToken
	}

	if len(aud) == 0 {
		return ErrJWTMissingClaims
	}

	if !audienceMatches(v.audiences, aud) {
		return ErrJWTInvalidAudience
	}

	return nil
}

func audienceMatches(expected []string, actual jwt.ClaimStrings) bool {
	if len(actual) == 0 || len(expected) == 0 {
		return false
	}

	set := make(map[string]struct{}, len(actual))
	for _, audience := range actual {
		set[audience] = struct{}{}
	}

	for _, audience := range expected {
		if _, ok := set[audience]; ok {
			return true
		}
	}

	return false
}

func containsString(values []string, target string) bool {
	return slices.Contains(values, target)
}
