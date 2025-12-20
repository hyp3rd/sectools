// Package io provides utility functions for client operations,
// including gRPC error handling and secure file operations.
package io

import (
	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"

	"github.com/hyp3rd/sectools/internal/io"
	"github.com/hyp3rd/sectools/internal/memory"
)

// SecureReadFile reads a file securely and returns the contents as a byte slice.
// The file contents are read into memory and should be handled carefully.
func SecureReadFile(file string, log hyperlogger.Logger) ([]byte, error) {
	if log != nil {
		log.WithField("file", file).Debug("Reading file securely")
	}

	err := validateFile(file)
	if err != nil {
		return nil, err
	}

	return io.SecureReadFile(file, log)
}

// SecureReadFileWithSecureBuffer reads a file securely and returns the contents
// in a SecureBuffer for better memory protection.
func SecureReadFileWithSecureBuffer(filename string, log hyperlogger.Logger) (*memory.SecureBuffer, error) {
	if log != nil {
		log.WithField("file", filename).Debug("Reading file securely into secure buffer")
	}

	err := validateFile(filename)
	if err != nil {
		return nil, err
	}

	return io.SecureReadFileWithSecureBuffer(filename, log)
}

// validateFile checks if the given filename is valid by ensuring it is not empty
// and verifying the file path using SecurePath. It returns an error if the
// filename is invalid or the path cannot be secured.
func validateFile(filename string) error {
	if filename == "" {
		return ewrap.New("path cannot be empty")
	}

	_, err := io.SecurePath(filename)
	if err != nil {
		return ewrap.Wrap(err, "invalid file path")
	}

	return nil
}
