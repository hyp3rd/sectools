package mfa

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidMFAConfig indicates the MFA configuration is invalid.
	ErrInvalidMFAConfig = ewrap.New("invalid mfa config")
	// ErrMFAMissingIssuer indicates the issuer is required.
	ErrMFAMissingIssuer = ewrap.New("mfa issuer is required")
	// ErrMFAMissingAccountName indicates the account name is required.
	ErrMFAMissingAccountName = ewrap.New("mfa account name is required")
	// ErrMFAInvalidSecret indicates the secret is invalid.
	ErrMFAInvalidSecret = ewrap.New("mfa secret is invalid")
	// ErrMFASecretTooShort indicates the secret is too short.
	ErrMFASecretTooShort = ewrap.New("mfa secret is too short")
	// ErrMFASecretTooLong indicates the secret is too long.
	ErrMFASecretTooLong = ewrap.New("mfa secret is too long")
	// ErrMFAInvalidCode indicates the otp code is invalid.
	ErrMFAInvalidCode = ewrap.New("mfa otp code is invalid")
	// ErrMFAInvalidCounter indicates the hotp counter is invalid.
	ErrMFAInvalidCounter = ewrap.New("mfa counter is invalid")
)
