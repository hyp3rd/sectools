package memory

import (
	"io"

	"github.com/hyp3rd/ewrap"
)

// NewSecureBufferFromReader reads up to maxBytes from reader into a SecureBuffer.
// maxBytes must be positive and fit into the platform int size.
func NewSecureBufferFromReader(reader io.Reader, maxBytes int64) (*SecureBuffer, error) {
	if reader == nil {
		return nil, ErrNilReader
	}

	maxInt := int64(^uint(0) >> 1)
	if maxBytes <= 0 || maxBytes >= maxInt {
		return nil, ErrMaxSizeInvalid
	}

	limited := io.LimitReader(reader, maxBytes+1)

	data, err := io.ReadAll(limited)
	if err != nil {
		ZeroBytes(data)

		return nil, ewrap.Wrap(err, "failed to read data")
	}

	if int64(len(data)) > maxBytes {
		ZeroBytes(data)

		return nil, ErrBufferTooLarge
	}

	secureBuffer := NewSecureBuffer(data)
	ZeroBytes(data)

	return secureBuffer, nil
}
