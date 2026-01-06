package io

import (
	"os"

	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// SecureTempFile creates a temp file securely using the provided options.
func SecureTempFile(prefix string, opts SecureTempOptions, log hyperlogger.Logger) (*os.File, error) {
	if log != nil {
		log.WithField("prefix", prefix).Debug("Creating temp file securely")
	}

	return internalio.SecureTempFile(prefix, toInternalTempOptions(opts), log)
}

// SecureTempDir creates a temp directory securely using the provided options.
func SecureTempDir(prefix string, opts SecureDirOptions, log hyperlogger.Logger) (string, error) {
	if log != nil {
		log.WithField("prefix", prefix).Debug("Creating temp directory securely")
	}

	return internalio.SecureTempDir(prefix, toInternalDirOptions(opts), log)
}
