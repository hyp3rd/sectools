package mfa

import "github.com/pquerna/otp"

// Algorithm defines the HMAC algorithm used by OTP.
type Algorithm = otp.Algorithm

const (
	// AlgorithmSHA1 uses HMAC-SHA1.
	AlgorithmSHA1 = otp.AlgorithmSHA1
	// AlgorithmSHA256 uses HMAC-SHA256.
	AlgorithmSHA256 = otp.AlgorithmSHA256
	// AlgorithmSHA512 uses HMAC-SHA512.
	AlgorithmSHA512 = otp.AlgorithmSHA512
)

// Digits defines the number of digits in OTP codes.
type Digits = otp.Digits

const (
	// DigitsSix uses 6-digit OTP codes.
	DigitsSix = otp.DigitsSix
	// DigitsEight uses 8-digit OTP codes.
	DigitsEight = otp.DigitsEight
)

// RateLimiter enforces rate limiting for MFA verification attempts.
type RateLimiter interface {
	Allow() (bool, error)
}
