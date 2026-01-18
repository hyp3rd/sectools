package limits

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidLimitConfig indicates an invalid limits configuration.
	ErrInvalidLimitConfig = ewrap.New("invalid limits config")
	// ErrInvalidLimitInput indicates the input or target is invalid.
	ErrInvalidLimitInput = ewrap.New("invalid limits input")
	// ErrLimitExceeded indicates the input exceeded the configured limit.
	ErrLimitExceeded = ewrap.New("input exceeds limit")
	// ErrReadFailed indicates the input could not be read.
	ErrReadFailed = ewrap.New("input read failed")
	// ErrDecodeFailed indicates the input could not be decoded.
	ErrDecodeFailed = ewrap.New("input decode failed")
)
