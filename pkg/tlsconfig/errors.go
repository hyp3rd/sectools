package tlsconfig

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidTLSConfig indicates the TLS configuration is invalid.
	ErrInvalidTLSConfig = ewrap.New("invalid tls config")
	// ErrTLSVersionTooLow indicates the TLS version is too low.
	ErrTLSVersionTooLow = ewrap.New("tls version too low")
	// ErrTLSVersionRange indicates the TLS version range is invalid.
	ErrTLSVersionRange = ewrap.New("tls version range invalid")
	// ErrTLSMissingCertificate indicates server certificates are required.
	ErrTLSMissingCertificate = ewrap.New("tls certificate required")
	// ErrTLSInvalidCipherSuites indicates the cipher suite list is invalid.
	ErrTLSInvalidCipherSuites = ewrap.New("tls cipher suites invalid")
	// ErrTLSInvalidCurvePreferences indicates the curve preferences are invalid.
	ErrTLSInvalidCurvePreferences = ewrap.New("tls curve preferences invalid")
	// ErrTLSMissingClientCAs indicates client CAs are required for mTLS verification.
	ErrTLSMissingClientCAs = ewrap.New("tls client ca required")
)
