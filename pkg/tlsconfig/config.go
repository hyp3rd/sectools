package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"strings"
)

const (
	tlsDefaultMinVersion = tls.VersionTLS13
)

// Option configures TLS settings.
type Option func(*config) error

type config struct {
	minVersion           uint16
	maxVersion           uint16
	cipherSuites         []uint16
	curvePreferences     []tls.CurveID
	nextProtos           []string
	serverName           string
	rootCAs              *x509.CertPool
	clientCAs            *x509.CertPool
	certificates         []tls.Certificate
	getCertificate       func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	clientAuth           tls.ClientAuthType
	insecureSkipVerify   bool
	keyLogWriter         io.Writer
}

// NewClientConfig returns a TLS client config with safe defaults.
func NewClientConfig(opts ...Option) (*tls.Config, error) {
	cfg, err := applyOptions(opts)
	if err != nil {
		return nil, err
	}

	err = validateCommonConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:           cfg.minVersion, // #nosec G402 -- validated against tls.VersionTLS12 in validateCommonConfig.
		MaxVersion:           cfg.maxVersion,
		CipherSuites:         cfg.cipherSuites,
		CurvePreferences:     cfg.curvePreferences,
		NextProtos:           cfg.nextProtos,
		ServerName:           cfg.serverName,
		RootCAs:              cfg.rootCAs,
		Certificates:         cfg.certificates,
		GetClientCertificate: cfg.getClientCertificate,
		InsecureSkipVerify:   cfg.insecureSkipVerify, // #nosec G402 -- explicit opt-in for local/testing use.
		KeyLogWriter:         cfg.keyLogWriter,
	}, nil
}

// NewServerConfig returns a TLS server config with safe defaults.
func NewServerConfig(opts ...Option) (*tls.Config, error) {
	cfg, err := applyOptions(opts)
	if err != nil {
		return nil, err
	}

	err = validateCommonConfig(cfg)
	if err != nil {
		return nil, err
	}

	err = validateServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:               cfg.minVersion, // #nosec G402 -- validated against tls.VersionTLS12 in validateCommonConfig.
		MaxVersion:               cfg.maxVersion,
		CipherSuites:             cfg.cipherSuites,
		CurvePreferences:         cfg.curvePreferences,
		NextProtos:               cfg.nextProtos,
		Certificates:             cfg.certificates,
		GetCertificate:           cfg.getCertificate,
		ClientAuth:               cfg.clientAuth,
		ClientCAs:                cfg.clientCAs,
		// PreferServerCipherSuites is deprecated in Go 1.17+ and ignored for TLS 1.3,
		// but we keep it enabled for TLS 1.2 compatibility.
		PreferServerCipherSuites: true,
		KeyLogWriter:             cfg.keyLogWriter,
	}, nil
}

// WithMinVersion sets the minimum TLS version.
func WithMinVersion(version uint16) Option {
	return func(cfg *config) error {
		if version == 0 {
			return ErrInvalidTLSConfig
		}

		cfg.minVersion = version

		return nil
	}
}

// WithMaxVersion sets the maximum TLS version.
func WithMaxVersion(version uint16) Option {
	return func(cfg *config) error {
		cfg.maxVersion = version

		return nil
	}
}

// WithTLS13Only forces TLS 1.3 only.
func WithTLS13Only() Option {
	return func(cfg *config) error {
		cfg.minVersion = tls.VersionTLS13
		cfg.maxVersion = tls.VersionTLS13

		return nil
	}
}

// WithPostQuantumKeyExchange enables hybrid post-quantum key exchange.
// It prepends X25519MLKEM768 to the curve preferences for TLS 1.3 handshakes.
func WithPostQuantumKeyExchange() Option {
	return func(cfg *config) error {
		cfg.curvePreferences = enablePostQuantumCurves(cfg.curvePreferences)

		return nil
	}
}

// WithCipherSuites sets the TLS 1.2 cipher suites.
func WithCipherSuites(suites ...uint16) Option {
	return func(cfg *config) error {
		if len(suites) == 0 {
			return ErrInvalidTLSConfig
		}

		cfg.cipherSuites = append([]uint16(nil), suites...)

		return nil
	}
}

// WithCurvePreferences sets the elliptic curve preferences.
func WithCurvePreferences(curves ...tls.CurveID) Option {
	return func(cfg *config) error {
		if len(curves) == 0 {
			return ErrInvalidTLSConfig
		}

		cfg.curvePreferences = append([]tls.CurveID(nil), curves...)

		return nil
	}
}

// WithNextProtos sets the ALPN protocols.
func WithNextProtos(protos ...string) Option {
	return func(cfg *config) error {
		clean := make([]string, 0, len(protos))
		for _, proto := range protos {
			value := strings.TrimSpace(proto)
			if value == "" {
				continue
			}

			clean = append(clean, value)
		}

		if len(clean) == 0 {
			return ErrInvalidTLSConfig
		}

		cfg.nextProtos = clean

		return nil
	}
}

// WithServerName sets the server name for client TLS verification.
func WithServerName(name string) Option {
	return func(cfg *config) error {
		value := strings.TrimSpace(name)
		if value == "" {
			return ErrInvalidTLSConfig
		}

		cfg.serverName = value

		return nil
	}
}

// WithRootCAs sets the root CA pool for client TLS verification.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(cfg *config) error {
		if pool == nil {
			return ErrInvalidTLSConfig
		}

		cfg.rootCAs = pool

		return nil
	}
}

// WithClientCAs sets the client CA pool for mTLS verification.
func WithClientCAs(pool *x509.CertPool) Option {
	return func(cfg *config) error {
		if pool == nil {
			return ErrInvalidTLSConfig
		}

		cfg.clientCAs = pool

		return nil
	}
}

// WithCertificates sets the TLS certificates.
func WithCertificates(certs ...tls.Certificate) Option {
	return func(cfg *config) error {
		if len(certs) == 0 {
			return ErrInvalidTLSConfig
		}

		cfg.certificates = append([]tls.Certificate(nil), certs...)

		return nil
	}
}

// WithGetCertificate sets a certificate callback for servers.
func WithGetCertificate(fn func(*tls.ClientHelloInfo) (*tls.Certificate, error)) Option {
	return func(cfg *config) error {
		if fn == nil {
			return ErrInvalidTLSConfig
		}

		cfg.getCertificate = fn

		return nil
	}
}

// WithGetClientCertificate sets a certificate callback for clients.
func WithGetClientCertificate(fn func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return func(cfg *config) error {
		if fn == nil {
			return ErrInvalidTLSConfig
		}

		cfg.getClientCertificate = fn

		return nil
	}
}

// WithClientAuth sets the client authentication mode for servers.
func WithClientAuth(auth tls.ClientAuthType) Option {
	return func(cfg *config) error {
		cfg.clientAuth = auth

		return nil
	}
}

// WithInsecureSkipVerify disables certificate verification (not recommended).
func WithInsecureSkipVerify(allow bool) Option {
	return func(cfg *config) error {
		cfg.insecureSkipVerify = allow

		return nil
	}
}

// WithKeyLogWriter enables TLS key logging for debugging.
func WithKeyLogWriter(writer io.Writer) Option {
	return func(cfg *config) error {
		if writer == nil {
			return ErrInvalidTLSConfig
		}

		cfg.keyLogWriter = writer

		return nil
	}
}

func applyOptions(opts []Option) (config, error) {
	cfg := config{
		minVersion:       tlsDefaultMinVersion,
		cipherSuites:     defaultCipherSuites(),
		curvePreferences: defaultCurvePreferences(),
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(&cfg)
		if err != nil {
			return config{}, err
		}
	}

	return cfg, nil
}

func validateCommonConfig(cfg config) error {
	if cfg.minVersion < tlsDefaultMinVersion {
		return ErrTLSVersionTooLow
	}

	if cfg.maxVersion != 0 {
		if cfg.maxVersion < tlsDefaultMinVersion {
			return ErrTLSVersionTooLow
		}
		if cfg.maxVersion < cfg.minVersion {
			return ErrTLSVersionRange
		}
	}

	// Cipher suite configuration is only relevant for TLS versions below 1.3.
	// When TLS 1.3 is used exclusively (minVersion >= tls.VersionTLS13),
	// cipher suites cannot be configured and are ignored by crypto/tls, so
	// we skip this validation in that case.
	if cfg.minVersion < tls.VersionTLS13 {
		if len(cfg.cipherSuites) == 0 || !areCipherSuitesAllowed(cfg.cipherSuites) {
			return ErrTLSInvalidCipherSuites
		}
	}

	if len(cfg.curvePreferences) == 0 || !areCurvesAllowed(cfg.curvePreferences) {
		return ErrTLSInvalidCurvePreferences
	}

	for _, proto := range cfg.nextProtos {
		if strings.TrimSpace(proto) == "" {
			return ErrInvalidTLSConfig
		}
	}

	return nil
}

func validateServerConfig(cfg config) error {
	if len(cfg.certificates) == 0 && cfg.getCertificate == nil {
		return ErrTLSMissingCertificate
	}

	if requiresClientCAs(cfg.clientAuth) && cfg.clientCAs == nil {
		return ErrTLSMissingClientCAs
	}

	return nil
}

func requiresClientCAs(auth tls.ClientAuthType) bool {
	return auth == tls.RequireAndVerifyClientCert || auth == tls.VerifyClientCertIfGiven
}

func areCipherSuitesAllowed(suites []uint16) bool {
	allowed := allowedCipherSuites()
	for _, suite := range suites {
		if _, ok := allowed[suite]; !ok {
			return false
		}
	}

	return true
}

func areCurvesAllowed(curves []tls.CurveID) bool {
	allowed := allowedCurvePreferences()
	for _, curve := range curves {
		if _, ok := allowed[curve]; !ok {
			return false
		}
	}

	return true
}

func defaultCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

func allowedCipherSuites() map[uint16]struct{} {
	return map[uint16]struct{}{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {},
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {},
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {},
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {},
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  {},
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    {},
	}
}

func defaultCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

func allowedCurvePreferences() map[tls.CurveID]struct{} {
	return map[tls.CurveID]struct{}{
		tls.X25519MLKEM768: {},
		tls.X25519:         {},
		tls.CurveP256:      {},
		tls.CurveP384:      {},
	}
}

func enablePostQuantumCurves(curves []tls.CurveID) []tls.CurveID {
	remaining := make([]tls.CurveID, 0, len(curves))
	for _, existing := range curves {
		if existing == tls.X25519MLKEM768 || existing == tls.X25519 {
			continue
		}

		remaining = append(remaining, existing)
	}

	result := make([]tls.CurveID, 0, 2+len(remaining))
	result = append(result, tls.X25519MLKEM768, tls.X25519)
	result = append(result, remaining...)

	return result
}
