package password

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidParams indicates that the provided password parameters are invalid.
	ErrInvalidParams = ewrap.New("invalid password parameters")
	// ErrInvalidHash indicates that the provided password hash is invalid.
	ErrInvalidHash = ewrap.New("invalid password hash")
	// ErrPasswordTooLong indicates that the provided password is too long.
	ErrPasswordTooLong = ewrap.New("password is too long")
)
