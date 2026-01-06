package io

import (
	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// SecureCopyFile copies a file securely using the provided options.
func SecureCopyFile(src, dest string, opts SecureCopyOptions, log hyperlogger.Logger) error {
	if log != nil {
		log.WithField("src", src).WithField("dest", dest).Debug("Copying file securely")
	}

	return internalio.SecureCopyFile(
		src,
		dest,
		toInternalReadOptions(opts.Read),
		toInternalWriteOptions(opts.Write),
		opts.VerifyChecksum,
		log,
	)
}
