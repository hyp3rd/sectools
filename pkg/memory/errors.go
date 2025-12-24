package memory

import "github.com/hyp3rd/ewrap"

var (
	// ErrNilReader indicates a nil reader was provided.
	ErrNilReader = ewrap.New("reader cannot be nil")
	// ErrMaxSizeInvalid indicates max size is non-positive or exceeds platform limits.
	ErrMaxSizeInvalid = ewrap.New("max size must be positive and fit into int")
	// ErrBufferTooLarge indicates the data exceeds the configured maximum size.
	ErrBufferTooLarge = ewrap.New("data exceeds maximum size")
)
