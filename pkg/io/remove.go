package io

import (
	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// SecureRemove removes a file or empty directory securely using the provided options.
func SecureRemove(path string, opts SecureRemoveOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("path", path).Debug("Removing path securely")
	}

	return internalio.SecureRemove(path, toInternalRemoveOptions(opts), log)
}

// SecureRemoveAll removes a directory tree securely using the provided options.
func SecureRemoveAll(path string, opts SecureRemoveOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("path", path).Debug("Removing path tree securely")
	}

	return internalio.SecureRemoveAll(path, toInternalRemoveOptions(opts), log)
}
