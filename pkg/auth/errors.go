package auth

import "github.com/hyp3rd/ewrap"

var (
	// JWT Errors.

	// ErrJWTInvalidConfig indicates that the JWT configuration is invalid.
	ErrJWTInvalidConfig = ewrap.New("invalid jwt config")
	// ErrJWTMissingKey indicates that the JWT key is missing.
	ErrJWTMissingKey = ewrap.New("jwt key is required")
	// ErrJWTMissingSigningAlg indicates that the JWT signing algorithm is missing.
	ErrJWTMissingSigningAlg = ewrap.New("jwt signing algorithm is required")
	// ErrJWTMissingAllowedAlgs indicates that the JWT allowed algorithms are missing.
	ErrJWTMissingAllowedAlgs = ewrap.New("jwt allowed algorithms are required")
	// ErrJWTMissingClaims indicates that the JWT claims are missing.
	ErrJWTMissingClaims = ewrap.New("jwt claims are required")
	// ErrJWTMissingExpiration indicates that the JWT expiration is missing.
	ErrJWTMissingExpiration = ewrap.New("jwt expiration is required")
	// ErrJWTMissingKeyID indicates that the JWT key ID is missing.
	ErrJWTMissingKeyID = ewrap.New("jwt key id is required")
	// ErrJWTInvalidAudience indicates that the JWT audience is invalid.
	ErrJWTInvalidAudience = ewrap.New("jwt audience is invalid")
	// ErrJWTInvalidToken indicates that the JWT token is invalid.
	ErrJWTInvalidToken = ewrap.New("jwt token is invalid")
	// ErrJWTConflictingOptions indicates that the JWT options are conflicting.
	ErrJWTConflictingOptions = ewrap.New("jwt options are conflicting")

	// Paseto Errors.

	// ErrPasetoInvalidConfig indicates that the Paseto configuration is invalid.
	ErrPasetoInvalidConfig = ewrap.New("invalid paseto config")
	// ErrPasetoMissingKey indicates that the Paseto key is missing.
	ErrPasetoMissingKey = ewrap.New("paseto key is required")
	// ErrPasetoMissingToken indicates that the Paseto token is missing.
	ErrPasetoMissingToken = ewrap.New("paseto token is required")
	// ErrPasetoMissingExpiry indicates that the Paseto expiration is missing.
	ErrPasetoMissingExpiry = ewrap.New("paseto expiration is required")
	// ErrPasetoExpired indicates that the Paseto token has expired.
	ErrPasetoExpired = ewrap.New("paseto token has expired")
	// ErrPasetoInvalidToken indicates that the Paseto token is invalid.
	ErrPasetoInvalidToken = ewrap.New("paseto token is invalid")
	// ErrPasetoConflictingOpts indicates that the Paseto options are conflicting.
	ErrPasetoConflictingOpts = ewrap.New("paseto options are conflicting")
)
