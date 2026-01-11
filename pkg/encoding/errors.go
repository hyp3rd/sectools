package encoding

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidBase64Config indicates an invalid base64 configuration.
	ErrInvalidBase64Config = ewrap.New("invalid base64 config")
	// ErrBase64Empty indicates the base64 input is empty.
	ErrBase64Empty = ewrap.New("base64 input is empty")
	// ErrBase64TooLong indicates the base64 input exceeds the configured max length.
	ErrBase64TooLong = ewrap.New("base64 input too long")
	// ErrBase64Invalid indicates the base64 input is invalid.
	ErrBase64Invalid = ewrap.New("base64 input is invalid")

	// ErrInvalidHexConfig indicates an invalid hex configuration.
	ErrInvalidHexConfig = ewrap.New("invalid hex config")
	// ErrHexEmpty indicates the hex input is empty.
	ErrHexEmpty = ewrap.New("hex input is empty")
	// ErrHexTooLong indicates the hex input exceeds the configured max length.
	ErrHexTooLong = ewrap.New("hex input too long")
	// ErrHexInvalid indicates the hex input is invalid.
	ErrHexInvalid = ewrap.New("hex input is invalid")

	// ErrInvalidJSONConfig indicates an invalid JSON configuration.
	ErrInvalidJSONConfig = ewrap.New("invalid json config")
	// ErrJSONTooLarge indicates the JSON input exceeds the configured max length.
	ErrJSONTooLarge = ewrap.New("json input too large")
	// ErrJSONInvalid indicates the JSON input is invalid.
	ErrJSONInvalid = ewrap.New("json input is invalid")
	// ErrJSONTrailingData indicates trailing JSON data was found.
	ErrJSONTrailingData = ewrap.New("json trailing data detected")
)
