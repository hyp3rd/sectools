package validate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	emailMaxAddressLength = 254
	emailMaxLocalLength   = 64
	emailMaxDomainLength  = 255
	emailMaxLabelLength   = 63
	emailMinLabelLength   = 1

	emailIPLiteralPrefix   = "["
	emailIPLiteralSuffix   = "]"
	emailIPv6LiteralPrefix = "ipv6:"

	emailDot = '.'
	emailAt  = '@'
)

// DNSResolver abstracts DNS lookups for email validation.
type DNSResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, name string) ([]string, error)
}

// EmailOption configures EmailValidator.
type EmailOption func(*emailOptions) error

type emailOptions struct {
	allowDisplayName     bool
	allowQuotedLocal     bool
	allowIPLiteral       bool
	allowIDN             bool
	requireTLD           bool
	verifyDomain         bool
	requireMX            bool
	allowARecordFallback bool
	resolver             DNSResolver
}

// EmailResult contains normalized email details.
type EmailResult struct {
	Address        string
	LocalPart      string
	Domain         string
	DomainASCII    string
	DomainVerified bool
	VerifiedByMX   bool
	VerifiedByA    bool
}

// EmailValidator validates email addresses with optional DNS checks.
type EmailValidator struct {
	opts emailOptions
}

// NewEmailValidator constructs a validator with optional configuration.
func NewEmailValidator(opts ...EmailOption) (*EmailValidator, error) {
	cfg := emailOptions{
		requireTLD:           true,
		allowARecordFallback: true,
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

	if cfg.verifyDomain && cfg.resolver == nil {
		cfg.resolver = net.DefaultResolver
	}

	return &EmailValidator{opts: cfg}, nil
}

// WithEmailAllowDisplayName permits display names like "Name <user@example.com>".
func WithEmailAllowDisplayName(allow bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.allowDisplayName = allow

		return nil
	}
}

// WithEmailAllowQuotedLocal permits quoted local parts.
func WithEmailAllowQuotedLocal(allow bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.allowQuotedLocal = allow

		return nil
	}
}

// WithEmailAllowIPLiteral permits [ip] literal domains.
func WithEmailAllowIPLiteral(allow bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.allowIPLiteral = allow

		return nil
	}
}

// WithEmailAllowIDN permits IDN domains and normalizes them to ASCII.
func WithEmailAllowIDN(allow bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.allowIDN = allow

		return nil
	}
}

// WithEmailRequireTLD requires a dot in the domain part.
func WithEmailRequireTLD(require bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.requireTLD = require

		return nil
	}
}

// WithEmailVerifyDomain enables MX/A lookups for domain verification.
func WithEmailVerifyDomain(verify bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.verifyDomain = verify

		return nil
	}
}

// WithEmailRequireMX enforces MX records when domain verification is enabled.
func WithEmailRequireMX(require bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.requireMX = require

		return nil
	}
}

// WithEmailAllowARecordFallback enables A/AAAA fallback when MX is missing.
func WithEmailAllowARecordFallback(allow bool) EmailOption {
	return func(cfg *emailOptions) error {
		cfg.allowARecordFallback = allow

		return nil
	}
}

// WithEmailDNSResolver sets a custom DNS resolver.
func WithEmailDNSResolver(resolver DNSResolver) EmailOption {
	return func(cfg *emailOptions) error {
		if resolver == nil {
			return ErrInvalidEmailConfig
		}

		cfg.resolver = resolver

		return nil
	}
}

// Validate validates an email address and optionally verifies its domain.
func (v *EmailValidator) Validate(ctx context.Context, input string) (EmailResult, error) {
	trimmed, err := normalizeEmailInput(input)
	if err != nil {
		return EmailResult{}, err
	}

	address, err := v.normalizeAddress(trimmed)
	if err != nil {
		return EmailResult{}, err
	}

	localPart, domain, err := splitEmail(address)
	if err != nil {
		return EmailResult{}, err
	}

	err = v.validateLocalPart(localPart)
	if err != nil {
		return EmailResult{}, err
	}

	domainInfo, err := v.validateDomain(domain)
	if err != nil {
		return EmailResult{}, err
	}

	result := EmailResult{
		Address:     address,
		LocalPart:   localPart,
		Domain:      domainInfo.normalized,
		DomainASCII: domainInfo.ascii,
	}

	err = v.applyDomainVerification(ctx, domainInfo, &result)
	if err != nil {
		return EmailResult{}, err
	}

	return result, nil
}

func normalizeEmailInput(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", ErrEmailEmpty
	}

	if len(trimmed) > emailMaxAddressLength {
		return "", ErrEmailAddressTooLong
	}

	return trimmed, nil
}

func (v *EmailValidator) normalizeAddress(input string) (string, error) {
	addr, err := mail.ParseAddress(input)
	if err != nil {
		addr = nil
	}

	if addr == nil {
		return input, nil
	}

	address := addr.Address
	if !v.opts.allowDisplayName && input != address {
		return "", ErrEmailDisplayName
	}

	return address, nil
}

func (v *EmailValidator) validateLocalPart(local string) error {
	if len(local) > emailMaxLocalLength {
		return ErrEmailLocalPartTooLong
	}

	return validateLocalPartSyntax(local, v.opts.allowQuotedLocal)
}

type emailDomainInfo struct {
	normalized  string
	ascii       string
	isIPLiteral bool
}

func (v *EmailValidator) validateDomain(domain string) (emailDomainInfo, error) {
	domainInfo, err := normalizeDomain(domain, v.opts.allowIDN)
	if err != nil {
		return emailDomainInfo{}, err
	}

	if domainInfo.isIPLiteral {
		if !v.opts.allowIPLiteral {
			return emailDomainInfo{}, ErrEmailIPLiteralNotAllowed
		}

		return domainInfo, nil
	}

	if len(domainInfo.ascii) > emailMaxDomainLength {
		return emailDomainInfo{}, ErrEmailDomainTooLong
	}

	if v.opts.requireTLD && !strings.ContainsRune(domainInfo.ascii, emailDot) {
		return emailDomainInfo{}, ErrEmailDomainInvalid
	}

	err = validateDomainLabels(domainInfo.ascii)
	if err != nil {
		return emailDomainInfo{}, err
	}

	return domainInfo, nil
}

func (v *EmailValidator) applyDomainVerification(ctx context.Context, domainInfo emailDomainInfo, result *EmailResult) error {
	if !v.opts.verifyDomain || domainInfo.isIPLiteral {
		return nil
	}

	if ctx == nil {
		return ErrEmailInvalid
	}

	verification, err := v.verifyDomain(ctx, domainInfo.ascii)
	if err != nil {
		return err
	}

	result.DomainVerified = verification.verified
	result.VerifiedByMX = verification.byMX
	result.VerifiedByA = verification.byA

	return nil
}

type domainVerification struct {
	verified bool
	byMX     bool
	byA      bool
}

func splitEmail(address string) (local, domain string, err error) {
	at := strings.LastIndexByte(address, emailAt)
	if at <= 0 || at >= len(address)-1 {
		return "", "", ErrEmailInvalid
	}

	local = address[:at]

	domain = address[at+1:]
	if local == "" || domain == "" {
		return "", "", ErrEmailInvalid
	}

	return local, domain, nil
}

func validateLocalPartSyntax(local string, allowQuoted bool) error {
	if isQuoted(local) {
		if !allowQuoted {
			return ErrEmailQuotedLocalPart
		}

		if !isValidQuotedLocal(local) {
			return ErrEmailLocalPartInvalid
		}

		return nil
	}

	if !isDotAtom(local) {
		return ErrEmailLocalPartInvalid
	}

	return nil
}

func isQuoted(local string) bool {
	return len(local) >= 2 && local[0] == '"' && local[len(local)-1] == '"'
}

func isValidQuotedLocal(local string) bool {
	if len(local) < 2 {
		return false
	}

	for _, r := range local {
		if r == '\n' || r == '\r' {
			return false
		}
	}

	return true
}

func isDotAtom(local string) bool {
	if local[0] == '.' || local[len(local)-1] == '.' {
		return false
	}

	parts := strings.SplitSeq(local, ".")
	for part := range parts {
		if part == "" {
			return false
		}

		for _, r := range part {
			if r > utf8.RuneSelf {
				return false
			}

			if !isAtext(byte(r)) {
				return false
			}
		}
	}

	return true
}

func isAtext(ch byte) bool {
	if ch >= 'A' && ch <= 'Z' {
		return true
	}

	if ch >= 'a' && ch <= 'z' {
		return true
	}

	if ch >= '0' && ch <= '9' {
		return true
	}

	switch ch {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}

func normalizeDomain(domain string, allowIDN bool) (emailDomainInfo, error) {
	normalized := strings.TrimSuffix(domain, string(emailDot))
	if normalized == "" {
		return emailDomainInfo{}, ErrEmailDomainInvalid
	}

	if strings.HasPrefix(normalized, emailIPLiteralPrefix) && strings.HasSuffix(normalized, emailIPLiteralSuffix) {
		literal := normalized[1 : len(normalized)-1]
		if ip := parseIPLiteral(literal); ip == nil {
			return emailDomainInfo{isIPLiteral: true}, ErrEmailDomainInvalid
		}

		return emailDomainInfo{
			normalized:  normalized,
			ascii:       normalized,
			isIPLiteral: true,
		}, nil
	}

	asciiDomain := normalized
	if !isASCII(normalized) {
		if !allowIDN {
			return emailDomainInfo{}, ErrEmailIDNNotAllowed
		}

		converted, err := idna.Lookup.ToASCII(normalized)
		if err != nil {
			return emailDomainInfo{}, ErrEmailDomainInvalid
		}

		asciiDomain = converted
	}

	asciiDomain = strings.ToLower(asciiDomain)

	return emailDomainInfo{
		normalized: normalized,
		ascii:      asciiDomain,
	}, nil
}

func parseIPLiteral(literal string) net.IP {
	lower := strings.ToLower(literal)
	if strings.HasPrefix(lower, emailIPv6LiteralPrefix) {
		value := literal[len(emailIPv6LiteralPrefix):]

		return net.ParseIP(value)
	}

	return net.ParseIP(literal)
}

func isASCII(value string) bool {
	for i := range len(value) {
		if value[i] > utf8.RuneSelf {
			return false
		}
	}

	return true
}

func validateDomainLabels(domain string) error {
	labels := strings.SplitSeq(domain, ".")
	for label := range labels {
		err := validateDomainLabel(label)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateDomainLabel(label string) error {
	if len(label) < emailMinLabelLength || len(label) > emailMaxLabelLength {
		return ErrEmailDomainInvalid
	}

	if label[0] == '-' || label[len(label)-1] == '-' {
		return ErrEmailDomainInvalid
	}

	for i := range len(label) {
		if !isLabelChar(label[i]) {
			return ErrEmailDomainInvalid
		}
	}

	return nil
}

func isLabelChar(ch byte) bool {
	if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
		return true
	}

	return ch >= 'A' && ch <= 'Z'
}

func (v *EmailValidator) verifyDomain(ctx context.Context, domain string) (domainVerification, error) {
	mxRecords, err := v.opts.resolver.LookupMX(ctx, domain)
	if err == nil && hasValidMX(mxRecords) {
		return domainVerification{verified: true, byMX: true}, nil
	}

	if v.opts.requireMX {
		if err != nil {
			return domainVerification{}, fmt.Errorf("%w: %w", ErrEmailDomainLookupFailed, err)
		}

		return domainVerification{}, ErrEmailDomainUnverified
	}

	if v.opts.allowARecordFallback {
		hosts, hostErr := v.opts.resolver.LookupHost(ctx, domain)
		if hostErr == nil && len(hosts) > 0 {
			return domainVerification{verified: true, byA: true}, nil
		}

		if hostErr != nil && !isNotFound(hostErr) {
			return domainVerification{}, fmt.Errorf("%w: %w", ErrEmailDomainLookupFailed, hostErr)
		}
	}

	if err != nil && !isNotFound(err) {
		return domainVerification{}, fmt.Errorf("%w: %w", ErrEmailDomainLookupFailed, err)
	}

	return domainVerification{}, ErrEmailDomainUnverified
}

func hasValidMX(records []*net.MX) bool {
	for _, record := range records {
		if record == nil {
			continue
		}

		if strings.TrimSpace(record.Host) == "." {
			continue
		}

		if strings.TrimSpace(record.Host) == "" {
			continue
		}

		return true
	}

	return false
}

func isNotFound(err error) bool {
	dnsErr := &net.DNSError{}
	ok := errors.As(err, &dnsErr)

	return ok && dnsErr.IsNotFound
}
