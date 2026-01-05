// Package io provides secure file read and write helpers, including
// path validation and secure-buffer convenience functions.
package io

import (
	"io"
	"os"

	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
	"github.com/hyp3rd/sectools/pkg/memory"
)

// SecureReadFile reads a file securely and returns the contents as a byte slice.
// The file contents are read into memory and should be handled carefully.
func SecureReadFile(file string, log hyperlogger.Logger) ([]byte, error) {
	if log != nil {
		log.WithField("file", file).Debug("Reading file securely")
	}

	return internalio.SecureReadFile(file, log)
}

// SecureReadFileWithOptions reads a file securely using the provided options.
func SecureReadFileWithOptions(file string, opts SecureReadOptions, log hyperlogger.Logger) ([]byte, error) {
	if log != nil {
		log.WithField("file", file).Debug("Reading file securely with options")
	}

	return internalio.SecureReadFileWithOptions(file, toInternalReadOptions(opts), log)
}

// SecureReadFileWithMaxSize reads a file securely and rejects files larger than maxBytes.
func SecureReadFileWithMaxSize(file string, maxBytes int64, log hyperlogger.Logger) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, ErrMaxSizeInvalid
	}

	if log != nil {
		log.WithField("file", file).Debug("Reading file securely with max size")
	}

	return internalio.SecureReadFileWithOptions(file, toInternalReadOptions(SecureReadOptions{
		MaxSizeBytes: maxBytes,
	}), log)
}

// SecureOpenFile opens a file for streaming reads using the provided options.
func SecureOpenFile(file string, opts SecureReadOptions, log hyperlogger.Logger) (*os.File, error) {
	if log != nil {
		log.WithField("file", file).Debug("Opening file securely")
	}

	return internalio.SecureOpenFile(file, toInternalReadOptions(opts), log)
}

// SecureReadFileWithSecureBuffer reads a file securely and returns the contents
// in a SecureBuffer for better memory protection.
func SecureReadFileWithSecureBuffer(filename string, log hyperlogger.Logger) (*memory.SecureBuffer, error) {
	if log != nil {
		log.WithField("file", filename).Debug("Reading file securely into secure buffer")
	}

	return internalio.SecureReadFileWithSecureBuffer(filename, log)
}

// SecureReadFileWithSecureBufferOptions reads a file securely using the provided options
// and returns the contents in a SecureBuffer.
func SecureReadFileWithSecureBufferOptions(
	filename string,
	opts SecureReadOptions,
	log hyperlogger.Logger,
) (*memory.SecureBuffer, error) {
	if log != nil {
		log.WithField("file", filename).Debug("Reading file securely into secure buffer with options")
	}

	return internalio.SecureReadFileWithSecureBufferOptions(filename, toInternalReadOptions(opts), log)
}

// SecureWriteFile writes data to a file securely using the provided options.
func SecureWriteFile(file string, data []byte, opts SecureWriteOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("file", file).Debug("Writing file securely")
	}

	return internalio.SecureWriteFile(file, data, toInternalWriteOptions(opts), log)
}

// SecureWriteFromReader writes data from a reader to a file securely using the provided options.
func SecureWriteFromReader(file string, reader io.Reader, opts SecureWriteOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("file", file).Debug("Writing file securely from reader")
	}

	return internalio.SecureWriteFromReader(file, reader, toInternalWriteOptions(opts), log)
}
