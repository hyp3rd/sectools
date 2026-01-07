package io

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

// SecureCopyFile copies a file securely with configurable options.
func SecureCopyFile(
	src string,
	dest string,
	readOpts ReadOptions,
	writeOpts WriteOptions,
	verifyChecksum bool,
	log hyperlogger.Logger,
) error {
	file, _, err := openFileWithOptions(src, readOpts, log)
	if err != nil {
		return err
	}
	defer closeFile(file, src, log)

	maxSize := effectiveMaxSize(readOpts.MaxSizeBytes, writeOpts.MaxSizeBytes)
	writeOpts.MaxSizeBytes = maxSize

	reader := io.Reader(file)

	var hasher hash.Hash

	if verifyChecksum {
		hasher = sha256.New()
		reader = io.TeeReader(reader, hasher)
	}

	err = SecureWriteFromReader(dest, reader, writeOpts, log)
	if err != nil {
		return err
	}

	if !verifyChecksum {
		return nil
	}

	sourceSum := hasher.Sum(nil)

	destSum, err := checksumFile(dest, readOptsFromWriteOptions(writeOpts, maxSize), log)
	if err != nil {
		return err
	}

	if !bytes.Equal(sourceSum, destSum) {
		return ErrChecksumMismatch.WithMetadata(pathLabel, dest)
	}

	return nil
}

func checksumFile(path string, opts ReadOptions, log hyperlogger.Logger) ([]byte, error) {
	file, _, err := openFileWithOptions(path, opts, log)
	if err != nil {
		return nil, err
	}
	defer closeFile(file, path, log)

	hasher := sha256.New()

	_, err = io.CopyBuffer(hasher, file, make([]byte, readerBufferSize))
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to copy buffer for checksum", ewrap.WithRetry(maxRetryAttempts, retryDelay))
	}

	return hasher.Sum(nil), nil
}

func readOptsFromWriteOptions(writeOpts WriteOptions, maxSize int64) ReadOptions {
	return ReadOptions{
		BaseDir:       writeOpts.BaseDir,
		AllowedRoots:  writeOpts.AllowedRoots,
		MaxSizeBytes:  maxSize,
		AllowAbsolute: writeOpts.AllowAbsolute,
		AllowSymlinks: writeOpts.AllowSymlinks,
		OwnerUID:      writeOpts.OwnerUID,
		OwnerGID:      writeOpts.OwnerGID,
	}
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
