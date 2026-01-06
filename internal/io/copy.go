package io

import (
	"github.com/hyp3rd/hyperlogger"
)

// SecureCopyFile copies a file securely with configurable options.
func SecureCopyFile(src, dest string, readOpts ReadOptions, writeOpts WriteOptions, log hyperlogger.Logger) error {
	file, _, err := openFileWithOptions(src, readOpts, log)
	if err != nil {
		return err
	}
	defer closeFile(file, src, log)

	writeOpts.MaxSizeBytes = effectiveMaxSize(readOpts.MaxSizeBytes, writeOpts.MaxSizeBytes)

	return SecureWriteFromReader(dest, file, writeOpts, log)
}

func effectiveMaxSize(readMax, writeMax int64) int64 {
	if readMax <= 0 {
		return writeMax
	}

	if writeMax <= 0 || readMax < writeMax {
		return readMax
	}

	return writeMax
}
