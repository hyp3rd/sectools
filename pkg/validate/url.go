package validate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	urlDefaultMaxLength    = 2048
	urlDefaultMaxRedirects = 10
	urlDefaultTimeout      = 5 * time.Second

	schemeHTTPS = "https"

	httpMethodHead = "HEAD"
	httpMethodGet  = "GET"

	redirectStatusMultipleChoices   = 300
	redirectStatusMovedPermanently  = 301
	redirectStatusFound             = 302
	redirectStatusSeeOther          = 303
	redirectStatusTemporaryRedirect = 307
	redirectStatusPermanentRedirect = 308
)

// URLReputationChecker evaluates a URL's reputation.
type URLReputationChecker interface {
	Check(ctx context.Context, target *url.URL) (ReputationResult, error)
}

// URLReputationCheckerFunc adapts a function to URLReputationChecker.
type URLReputationCheckerFunc func(ctx context.Context, target *url.URL) (ReputationResult, error)

// Check implements URLReputationChecker.
func (f URLReputationCheckerFunc) Check(ctx context.Context, target *url.URL) (ReputationResult, error) {
	return f(ctx, target)
}

// ReputationVerdict indicates reputation outcome.
type ReputationVerdict int

const (
	// ReputationUnknown indicates an unknown reputation verdict.
	ReputationUnknown ReputationVerdict = iota
	// ReputationAllowed indicates an allowed reputation verdict.
	ReputationAllowed
	// ReputationBlocked indicates a blocked reputation verdict.
	ReputationBlocked
)

// ReputationResult describes a reputation check result.
type ReputationResult struct {
	Verdict ReputationVerdict
	Reason  string
}

// StaticReputation checks against allow/block lists.
type StaticReputation struct {
	allow map[string]struct{}
	block map[string]struct{}
}

// NewStaticReputation constructs a static checker.
func NewStaticReputation(allowHosts, blockHosts []string) *StaticReputation {
	return &StaticReputation{
		allow: normalizeHostSet(allowHosts),
		block: normalizeHostSet(blockHosts),
	}
}

// Check implements URLReputationChecker.
func (s *StaticReputation) Check(_ context.Context, target *url.URL) (ReputationResult, error) {
	if target == nil {
		return ReputationResult{Verdict: ReputationUnknown}, nil
	}

	host := strings.ToLower(target.Hostname())
	if host == "" {
		return ReputationResult{Verdict: ReputationUnknown}, nil
	}

	if _, ok := s.block[host]; ok {
		return ReputationResult{Verdict: ReputationBlocked, Reason: "blocked"}, nil
	}

	if len(s.allow) > 0 {
		if _, ok := s.allow[host]; ok {
			return ReputationResult{Verdict: ReputationAllowed}, nil
		}

		return ReputationResult{Verdict: ReputationBlocked, Reason: "not allowed"}, nil
	}

	return ReputationResult{Verdict: ReputationUnknown}, nil
}

// URLOption configures URLValidator.
type URLOption func(*urlOptions) error

type urlOptions struct {
	allowedSchemes    map[string]struct{}
	allowUserInfo     bool
	allowIDN          bool
	allowIPLiteral    bool
	allowPrivateIP    bool
	allowLocalhost    bool
	maxLength         int
	checkRedirects    bool
	maxRedirects      int
	redirectMethod    string
	httpClient        *http.Client
	reputationChecker URLReputationChecker
	allowedHosts      map[string]struct{}
	blockedHosts      map[string]struct{}
}

// URLResult describes URL validation output.
type URLResult struct {
	NormalizedURL string
	FinalURL      string
	Redirects     []URLRedirect
	Reputation    ReputationResult
}

// URLRedirect captures a single redirect hop.
type URLRedirect struct {
	From       string
	To         string
	StatusCode int
}

// URLValidator validates URLs with optional redirect and reputation checks.
type URLValidator struct {
	opts urlOptions
}

// NewURLValidator constructs a validator with options.
func NewURLValidator(opts ...URLOption) (*URLValidator, error) {
	cfg := urlOptions{
		allowedSchemes: map[string]struct{}{
			schemeHTTPS: {},
		},
		maxLength:      urlDefaultMaxLength,
		maxRedirects:   urlDefaultMaxRedirects,
		redirectMethod: httpMethodHead,
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

	err := validateURLOptions(&cfg)
	if err != nil {
		return nil, err
	}

	return &URLValidator{opts: cfg}, nil
}

// WithURLAllowedSchemes sets allowed schemes.
func WithURLAllowedSchemes(schemes ...string) URLOption {
	return func(cfg *urlOptions) error {
		clean := make(map[string]struct{})

		for _, scheme := range schemes {
			value := strings.ToLower(strings.TrimSpace(scheme))
			if value == "" {
				continue
			}

			if value != schemeHTTPS {
				return ErrInvalidURLConfig
			}

			clean[value] = struct{}{}
		}

		if len(clean) == 0 {
			return ErrInvalidURLConfig
		}

		cfg.allowedSchemes = clean

		return nil
	}
}

// WithURLAllowUserInfo allows userinfo in URLs.
func WithURLAllowUserInfo(allow bool) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowUserInfo = allow

		return nil
	}
}

// WithURLAllowIDN allows IDN hostnames.
func WithURLAllowIDN(allow bool) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowIDN = allow

		return nil
	}
}

// WithURLAllowIPLiteral allows IP literal hosts.
func WithURLAllowIPLiteral(allow bool) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowIPLiteral = allow

		return nil
	}
}

// WithURLAllowPrivateIP allows private/loopback IPs.
func WithURLAllowPrivateIP(allow bool) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowPrivateIP = allow

		return nil
	}
}

// WithURLAllowLocalhost allows localhost hostnames.
func WithURLAllowLocalhost(allow bool) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowLocalhost = allow

		return nil
	}
}

// WithURLMaxLength sets the max URL length.
func WithURLMaxLength(maxLen int) URLOption {
	return func(cfg *urlOptions) error {
		if maxLen <= 0 {
			return ErrInvalidURLConfig
		}

		cfg.maxLength = maxLen

		return nil
	}
}

// WithURLCheckRedirects enables redirect checks with a max hop count.
func WithURLCheckRedirects(maxRedirects int) URLOption {
	return func(cfg *urlOptions) error {
		if maxRedirects <= 0 {
			return ErrInvalidURLConfig
		}

		cfg.checkRedirects = true
		cfg.maxRedirects = maxRedirects

		return nil
	}
}

// WithURLRedirectMethod sets the HTTP method for redirect checks.
func WithURLRedirectMethod(method string) URLOption {
	return func(cfg *urlOptions) error {
		value := strings.ToUpper(strings.TrimSpace(method))
		if value != httpMethodHead && value != httpMethodGet {
			return ErrInvalidURLConfig
		}

		cfg.redirectMethod = value

		return nil
	}
}

// WithURLHTTPClient sets a custom HTTP client for redirect checks.
func WithURLHTTPClient(client *http.Client) URLOption {
	return func(cfg *urlOptions) error {
		if client == nil {
			return ErrInvalidURLConfig
		}

		cfg.httpClient = client

		return nil
	}
}

// WithURLReputationChecker sets a reputation checker.
func WithURLReputationChecker(checker URLReputationChecker) URLOption {
	return func(cfg *urlOptions) error {
		if checker == nil {
			return ErrInvalidURLConfig
		}

		cfg.reputationChecker = checker

		return nil
	}
}

// WithURLAllowedHosts restricts validation to specific hosts.
func WithURLAllowedHosts(hosts ...string) URLOption {
	return func(cfg *urlOptions) error {
		cfg.allowedHosts = normalizeHostSet(hosts)

		return nil
	}
}

// WithURLBlockedHosts blocks specific hosts.
func WithURLBlockedHosts(hosts ...string) URLOption {
	return func(cfg *urlOptions) error {
		cfg.blockedHosts = normalizeHostSet(hosts)

		return nil
	}
}

// Validate validates the URL, optionally checking redirects and reputation.
func (v *URLValidator) Validate(ctx context.Context, raw string) (URLResult, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return URLResult{}, ErrURLInvalid
	}

	if len(trimmed) > v.opts.maxLength {
		return URLResult{}, ErrURLTooLong
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return URLResult{}, ErrURLInvalid
	}

	err = v.validateParsed(parsed)
	if err != nil {
		return URLResult{}, err
	}

	result := URLResult{
		NormalizedURL: parsed.String(),
		FinalURL:      parsed.String(),
	}

	if v.opts.reputationChecker != nil {
		err := v.checkReputation(ctx, parsed)
		if err != nil {
			return URLResult{}, err
		}
	}

	if v.opts.checkRedirects {
		finalURL, redirects, err := v.followRedirects(ctx, parsed)
		if err != nil {
			return URLResult{}, err
		}

		result.FinalURL = finalURL.String()
		result.Redirects = redirects

		if v.opts.reputationChecker != nil {
			err := v.checkReputation(ctx, finalURL)
			if err != nil {
				return URLResult{}, err
			}
		}
	}

	return result, nil
}

func validateURLOptions(cfg *urlOptions) error {
	if len(cfg.allowedSchemes) == 0 {
		return ErrInvalidURLConfig
	}

	if len(cfg.allowedSchemes) != 1 {
		return ErrInvalidURLConfig
	}

	if _, ok := cfg.allowedSchemes[schemeHTTPS]; !ok {
		return ErrInvalidURLConfig
	}

	if cfg.maxLength <= 0 {
		return ErrInvalidURLConfig
	}

	if cfg.checkRedirects && cfg.maxRedirects <= 0 {
		return ErrInvalidURLConfig
	}

	if cfg.redirectMethod != httpMethodHead && cfg.redirectMethod != httpMethodGet {
		return ErrInvalidURLConfig
	}

	return nil
}

func normalizeHostSet(hosts []string) map[string]struct{} {
	clean := make(map[string]struct{})

	for _, host := range hosts {
		value := strings.ToLower(strings.TrimSpace(host))
		if value == "" {
			continue
		}

		clean[value] = struct{}{}
	}

	return clean
}

func (v *URLValidator) validateParsed(parsed *url.URL) error {
	if parsed == nil {
		return ErrURLInvalid
	}

	err := v.validateScheme(parsed)
	if err != nil {
		return err
	}

	err = v.validateUserInfo(parsed)
	if err != nil {
		return err
	}

	host, err := v.normalizedHost(parsed)
	if err != nil {
		return err
	}

	err = v.validateHost(host)
	if err != nil {
		return err
	}

	return v.validateIPHost(host)
}

func (v *URLValidator) validateScheme(parsed *url.URL) error {
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		return ErrURLInvalid
	}

	if _, ok := v.opts.allowedSchemes[scheme]; !ok {
		return ErrURLSchemeNotAllowed
	}

	return nil
}

func (v *URLValidator) validateUserInfo(parsed *url.URL) error {
	if parsed.User != nil && !v.opts.allowUserInfo {
		return ErrURLUserInfoNotAllowed
	}

	return nil
}

func (v *URLValidator) normalizedHost(parsed *url.URL) (string, error) {
	host := parsed.Hostname()
	if host == "" {
		return "", ErrURLHostMissing
	}

	return normalizeHost(host, v.opts.allowIDN)
}

func (v *URLValidator) validateHost(host string) error {
	if !v.opts.allowLocalhost && isLocalhost(host) {
		return ErrURLHostNotAllowed
	}

	return v.checkHostRestrictions(host)
}

func (v *URLValidator) validateIPHost(host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}

	if !v.opts.allowIPLiteral {
		return ErrURLHostNotAllowed
	}

	if !v.opts.allowPrivateIP && isPrivateIP(ip) {
		return ErrURLPrivateIPNotAllowed
	}

	return nil
}

func normalizeHost(host string, allowIDN bool) (string, error) {
	normalized := strings.TrimSuffix(host, ".")
	if normalized == "" {
		return "", ErrURLHostMissing
	}

	if !isASCII(normalized) {
		if !allowIDN {
			return "", ErrURLHostNotAllowed
		}

		converted, err := idna.Lookup.ToASCII(normalized)
		if err != nil {
			return "", ErrURLHostNotAllowed
		}

		normalized = converted
	}

	return strings.ToLower(normalized), nil
}

func (v *URLValidator) checkHostRestrictions(host string) error {
	if _, ok := v.opts.blockedHosts[host]; ok {
		return ErrURLHostNotAllowed
	}

	if len(v.opts.allowedHosts) > 0 {
		if _, ok := v.opts.allowedHosts[host]; !ok {
			return ErrURLHostNotAllowed
		}
	}

	return nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip.IsPrivate() {
		return true
	}

	return ip.IsMulticast()
}

func (v *URLValidator) followRedirects(ctx context.Context, start *url.URL) (*url.URL, []URLRedirect, error) {
	if ctx == nil {
		return nil, nil, ErrURLInvalid
	}

	client := v.httpClient()
	current := start
	visited := make(map[string]struct{})
	redirects := make([]URLRedirect, 0)

	for range v.opts.maxRedirects {
		hopKey := current.String()
		if _, ok := visited[hopKey]; ok {
			return nil, nil, ErrURLRedirectLoop
		}

		visited[hopKey] = struct{}{}

		nextURL, redirect, err := v.nextRedirect(ctx, client, current)
		if err != nil {
			return nil, nil, err
		}

		if redirect == nil {
			return current, redirects, nil
		}

		redirects = append(redirects, *redirect)
		current = nextURL
	}

	return nil, nil, ErrURLRedirectLimit
}

func (v *URLValidator) nextRedirect(ctx context.Context, client *http.Client, current *url.URL) (*url.URL, *URLRedirect, error) {
	req, err := http.NewRequestWithContext(ctx, v.opts.redirectMethod, current.String(), nil)
	if err != nil {
		return nil, nil, ErrURLInvalid
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, ErrURLRedirectNotAllowed
	}

	//nolint:errcheck
	_ = resp.Body.Close()

	if !isRedirectStatus(resp.StatusCode) {
		return current, nil, nil
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, nil, ErrURLRedirectNotAllowed
	}

	nextURL, err := url.Parse(location)
	if err != nil {
		return nil, nil, ErrURLRedirectNotAllowed
	}

	nextURL = current.ResolveReference(nextURL)

	err = v.validateParsed(nextURL)
	if err != nil {
		return nil, nil, err
	}

	redirect := URLRedirect{
		From:       current.String(),
		To:         nextURL.String(),
		StatusCode: resp.StatusCode,
	}

	return nextURL, &redirect, nil
}

func isRedirectStatus(code int) bool {
	switch code {
	case redirectStatusMultipleChoices,
		redirectStatusMovedPermanently,
		redirectStatusFound,
		redirectStatusSeeOther,
		redirectStatusTemporaryRedirect,
		redirectStatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (v *URLValidator) httpClient() *http.Client {
	client := v.opts.httpClient
	if client == nil {
		client = &http.Client{Timeout: urlDefaultTimeout}
	}

	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &clone
}

func (v *URLValidator) checkReputation(ctx context.Context, target *url.URL) error {
	if ctx == nil {
		return ErrURLInvalid
	}

	result, err := v.opts.reputationChecker.Check(ctx, target)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrURLReputationFailed, err)
	}

	if result.Verdict == ReputationBlocked {
		return ErrURLReputationBlocked
	}

	return nil
}
