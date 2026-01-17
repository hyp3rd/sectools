package validate

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/idna"
)

type fakeResolver struct {
	mxRecords map[string][]*net.MX
	hosts     map[string][]string
	mxErr     map[string]error
	hostErr   map[string]error
}

func (r *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err, ok := r.mxErr[name]; ok {
		return nil, err
	}

	return r.mxRecords[name], nil
}

func (r *fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	if err, ok := r.hostErr[name]; ok {
		return nil, err
	}

	return r.hosts[name], nil
}

func TestEmailValidateBasic(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("expected valid email, got %v", err)
	}

	if result.DomainASCII != "example.com" {
		t.Fatalf("expected domain ascii, got %s", result.DomainASCII)
	}
}

func TestEmailRejectDisplayName(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "Name <user@example.com>")
	if !errors.Is(err, ErrEmailDisplayName) {
		t.Fatalf("expected ErrEmailDisplayName, got %v", err)
	}
}

func TestEmailAllowDisplayName(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator(WithEmailAllowDisplayName(true))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "Name <user@example.com>")
	if err != nil {
		t.Fatalf("expected valid email, got %v", err)
	}

	if result.Address != "user@example.com" {
		t.Fatalf("expected normalized address, got %s", result.Address)
	}
}

func TestEmailInvalidLocalPart(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "user..dot@example.com")
	if !errors.Is(err, ErrEmailLocalPartInvalid) {
		t.Fatalf("expected ErrEmailLocalPartInvalid, got %v", err)
	}
}

func TestEmailRequireTLD(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "user@localhost")
	if !errors.Is(err, ErrEmailDomainInvalid) {
		t.Fatalf("expected ErrEmailDomainInvalid, got %v", err)
	}
}

func TestEmailDomainVerificationMX(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		mxRecords: map[string][]*net.MX{
			"example.com": {{Host: "mx.example.com."}},
		},
	}

	validator, err := NewEmailValidator(
		WithEmailVerifyDomain(true),
		WithEmailDNSResolver(resolver),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("expected valid email, got %v", err)
	}

	if !result.DomainVerified || !result.VerifiedByMX {
		t.Fatalf("expected mx verification")
	}
}

func TestEmailDomainVerificationFallback(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		hosts: map[string][]string{
			"example.com": {"203.0.113.10"},
		},
	}

	validator, err := NewEmailValidator(
		WithEmailVerifyDomain(true),
		WithEmailDNSResolver(resolver),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("expected valid email, got %v", err)
	}

	if !result.DomainVerified || !result.VerifiedByA {
		t.Fatalf("expected A record verification")
	}
}

func TestEmailDomainVerificationUnverified(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{}

	validator, err := NewEmailValidator(
		WithEmailVerifyDomain(true),
		WithEmailDNSResolver(resolver),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "user@example.com")
	if !errors.Is(err, ErrEmailDomainUnverified) {
		t.Fatalf("expected ErrEmailDomainUnverified, got %v", err)
	}
}

func TestEmailAllowIDN(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator(WithEmailAllowIDN(true))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "user@bücher.example")
	if err != nil {
		t.Fatalf("expected valid email, got %v", err)
	}

	ascii, err := idna.Lookup.ToASCII("bücher.example")
	if err != nil {
		t.Fatalf("expected idna conversion, got %v", err)
	}

	if result.DomainASCII != ascii {
		t.Fatalf("expected ascii domain %s, got %s", ascii, result.DomainASCII)
	}
}

func TestEmailIPLiteralDisallowed(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "user@[127.0.0.1]")
	if !errors.Is(err, ErrEmailIPLiteralNotAllowed) {
		t.Fatalf("expected ErrEmailIPLiteralNotAllowed, got %v", err)
	}
}

func TestEmailIPLiteralAllowed(t *testing.T) {
	t.Parallel()

	validator, err := NewEmailValidator(WithEmailAllowIPLiteral(true))
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "user@[127.0.0.1]")
	if err != nil {
		t.Fatalf("expected valid ip-literal, got %v", err)
	}
}
