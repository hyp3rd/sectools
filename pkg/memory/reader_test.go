package memory

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hyp3rd/ewrap"
)

const errMsgUnexpected = "unexpected error: %v"

func TestNewSecureBufferFromReader(t *testing.T) {
	t.Parallel()

	input := []byte("secret")

	buf, err := NewSecureBufferFromReader(bytes.NewReader(input), int64(len(input)))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if got := buf.Bytes(); !bytes.Equal(got, input) {
		t.Fatalf("unexpected buffer contents: %q", string(got))
	}

	buf.Clear()
}

func TestNewSecureBufferFromReaderTooLarge(t *testing.T) {
	t.Parallel()

	_, err := NewSecureBufferFromReader(bytes.NewReader([]byte("secret")), 3)
	if !errors.Is(err, ErrBufferTooLarge) {
		t.Fatalf("expected ErrBufferTooLarge, got %v", err)
	}
}

func TestNewSecureBufferFromReaderInvalidMaxSize(t *testing.T) {
	t.Parallel()

	_, err := NewSecureBufferFromReader(bytes.NewReader([]byte("secret")), 0)
	if !errors.Is(err, ErrMaxSizeInvalid) {
		t.Fatalf("expected ErrMaxSizeInvalid, got %v", err)
	}
}

func TestNewSecureBufferFromReaderNilReader(t *testing.T) {
	t.Parallel()

	_, err := NewSecureBufferFromReader(nil, 10)
	if !errors.Is(err, ErrNilReader) {
		t.Fatalf("expected ErrNilReader, got %v", err)
	}
}

func TestNewSecureBufferFromReaderReadError(t *testing.T) {
	t.Parallel()

	readErr := ewrap.New("boom")
	reader := errorReader{err: readErr}

	_, err := NewSecureBufferFromReader(reader, 10)
	if err == nil {
		t.Fatal("expected read error")
	}

	if !strings.Contains(err.Error(), "failed to read data") {
		t.Fatalf(errMsgUnexpected, err)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}
