package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

const errMsgUnexpected = "expected config, got %v"

func TestClientConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := NewClientConfig()
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if cfg.MinVersion != tlsDefaultMinVersion {
		t.Fatalf("expected min version %d, got %d", tlsDefaultMinVersion, cfg.MinVersion)
	}

	if cfg.InsecureSkipVerify {
		t.Fatal("expected secure defaults")
	}

	if !uint16SliceEqual(cfg.CipherSuites, defaultCipherSuites()) {
		t.Fatal("unexpected cipher suites")
	}

	if !curveSliceEqual(cfg.CurvePreferences, defaultCurvePreferences()) {
		t.Fatal("unexpected curve preferences")
	}
}

func TestClientConfigTLS13Only(t *testing.T) {
	t.Parallel()

	cfg, err := NewClientConfig(WithTLS13Only())
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatal("expected tls 1.3 only")
	}
}

func TestClientConfigPostQuantum(t *testing.T) {
	t.Parallel()

	cfg, err := NewClientConfig(WithPostQuantumKeyExchange())
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	expected := []tls.CurveID{
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
	if !curveSliceEqual(cfg.CurvePreferences, expected) {
		t.Fatal("unexpected post-quantum curve preferences")
	}
}

func TestClientConfigRejectsWeakVersion(t *testing.T) {
	t.Parallel()

	_, err := NewClientConfig(WithMinVersion(tls.VersionTLS10))
	if !errors.Is(err, ErrTLSVersionTooLow) {
		t.Fatalf("expected ErrTLSVersionTooLow, got %v", err)
	}
}

func TestClientConfigRejectsWeakCipher(t *testing.T) {
	t.Parallel()

	_, err := NewClientConfig(WithCipherSuites(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA))
	if !errors.Is(err, ErrTLSInvalidCipherSuites) {
		t.Fatalf("expected ErrTLSInvalidCipherSuites, got %v", err)
	}
}

func TestServerConfigRequiresCertificate(t *testing.T) {
	t.Parallel()

	_, err := NewServerConfig()
	if !errors.Is(err, ErrTLSMissingCertificate) {
		t.Fatalf("expected ErrTLSMissingCertificate, got %v", err)
	}
}

func TestServerConfigWithCertificate(t *testing.T) {
	t.Parallel()

	cert, _ := testCertificate(t)

	_, err := NewServerConfig(WithCertificates(cert))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}
}

func TestServerConfigClientAuthRequiresCAs(t *testing.T) {
	t.Parallel()

	cert, _ := testCertificate(t)

	_, err := NewServerConfig(
		WithCertificates(cert),
		WithClientAuth(tls.RequireAndVerifyClientCert),
	)
	if !errors.Is(err, ErrTLSMissingClientCAs) {
		t.Fatalf("expected ErrTLSMissingClientCAs, got %v", err)
	}
}

func TestServerConfigClientAuthWithCAs(t *testing.T) {
	t.Parallel()

	cert, pool := testCertificate(t)

	_, err := NewServerConfig(
		WithCertificates(cert),
		WithClientAuth(tls.RequireAndVerifyClientCert),
		WithClientCAs(pool),
	)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("expected key, got %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("expected cert, got %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("expected parsed cert, got %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return cert, pool
}

func uint16SliceEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func curveSliceEqual(a, b []tls.CurveID) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
