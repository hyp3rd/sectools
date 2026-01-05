package io

import (
	"os"

	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// SecureReadDir reads a directory securely with default options.
func SecureReadDir(path string, log hyperlogger.Logger) ([]os.DirEntry, error) {
	if log != nil {
		log.WithField("path", path).Debug("Reading directory securely")
	}

	return internalio.SecureReadDir(path, log)
}

// SecureReadDirWithOptions reads a directory securely using the provided options.
func SecureReadDirWithOptions(path string, opts SecureReadOptions, log hyperlogger.Logger) ([]os.DirEntry, error) {
	if log != nil {
		log.WithField("path", path).Debug("Reading directory securely with options")
	}

	return internalio.SecureReadDirWithOptions(path, toInternalReadOptions(opts), log)
}

// SecureMkdirAll creates a directory securely using the provided options.
func SecureMkdirAll(path string, opts SecureDirOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("path", path).Debug("Creating directory securely")
	}

	return internalio.SecureMkdirAll(path, toInternalDirOptions(opts), log)
}
