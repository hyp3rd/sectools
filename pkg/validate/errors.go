package validate

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidEmailConfig indicates that the email validation configuration is invalid.
	ErrInvalidEmailConfig = ewrap.New("invalid email validation config")
	// ErrInvalidURLConfig indicates that the URL validation configuration is invalid.
	ErrInvalidURLConfig = ewrap.New("invalid url validation config")
	// ErrEmailEmpty indicates that the email is empty.
	ErrEmailEmpty = ewrap.New("email is empty")
	// ErrEmailInvalid indicates that the email is invalid.
	ErrEmailInvalid = ewrap.New("email is invalid")
	// ErrEmailDisplayName indicates that the email display name is not allowed.
	ErrEmailDisplayName = ewrap.New("email display name is not allowed")
	// ErrEmailLocalPartInvalid indicates that the email local part is invalid.
	ErrEmailLocalPartInvalid = ewrap.New("email local part is invalid")
	// ErrEmailDomainInvalid indicates that the email domain is invalid.
	ErrEmailDomainInvalid = ewrap.New("email domain is invalid")
	// ErrEmailDomainTooLong indicates that the email domain is too long.
	ErrEmailDomainTooLong = ewrap.New("email domain is too long")
	// ErrEmailLocalPartTooLong indicates that the email local part is too long.
	ErrEmailLocalPartTooLong = ewrap.New("email local part is too long")
	// ErrEmailAddressTooLong indicates that the email address is too long.
	ErrEmailAddressTooLong = ewrap.New("email address is too long")
	// ErrEmailQuotedLocalPart indicates that the email quoted local part is not allowed.
	ErrEmailQuotedLocalPart = ewrap.New("email quoted local part is not allowed")
	// ErrEmailIPLiteralNotAllowed indicates that the email ip-literal domain is not allowed.
	ErrEmailIPLiteralNotAllowed = ewrap.New("email ip-literal domain is not allowed")
	// ErrEmailIDNNotAllowed indicates that the email idn domains are not allowed.
	ErrEmailIDNNotAllowed = ewrap.New("email idn domains are not allowed")
	// ErrEmailDomainLookupFailed indicates that the email domain lookup failed.
	ErrEmailDomainLookupFailed = ewrap.New("email domain lookup failed")
	// ErrEmailDomainUnverified indicates that the email domain is unverified.
	ErrEmailDomainUnverified = ewrap.New("email domain is unverified")

	// ErrURLInvalid indicates that the URL is invalid.
	ErrURLInvalid = ewrap.New("url is invalid")
	// ErrURLTooLong indicates that the URL is too long.
	ErrURLTooLong = ewrap.New("url is too long")
	// ErrURLSchemeNotAllowed indicates that the URL scheme is not allowed.
	ErrURLSchemeNotAllowed = ewrap.New("url scheme is not allowed")
	// ErrURLHostMissing indicates that the URL host is required.
	ErrURLHostMissing = ewrap.New("url host is required")
	// ErrURLUserInfoNotAllowed indicates that the URL userinfo is not allowed.
	ErrURLUserInfoNotAllowed = ewrap.New("url userinfo is not allowed")
	// ErrURLHostNotAllowed indicates that the URL host is not allowed.
	ErrURLHostNotAllowed = ewrap.New("url host is not allowed")
	// ErrURLPrivateIPNotAllowed indicates that the URL private IP is not allowed.
	ErrURLPrivateIPNotAllowed = ewrap.New("url private ip is not allowed")
	// ErrURLRedirectNotAllowed indicates that URL redirects are not allowed.
	ErrURLRedirectNotAllowed = ewrap.New("url redirect is not allowed")
	// ErrURLRedirectLoop indicates that a URL redirect loop was detected.
	ErrURLRedirectLoop = ewrap.New("url redirect loop detected")
	// ErrURLRedirectLimit indicates that the URL redirect limit was exceeded.
	ErrURLRedirectLimit = ewrap.New("url redirect limit exceeded")
	// ErrURLReputationFailed indicates that the URL reputation check failed.
	ErrURLReputationFailed = ewrap.New("url reputation check failed")
	// ErrURLReputationBlocked indicates that the URL reputation check blocked the URL.
	ErrURLReputationBlocked = ewrap.New("url reputation blocked")
)
