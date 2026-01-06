package io

import (
	"io"
	"os"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

const (
	maxRetryAttempts = 3
	retryDelay       = 100 // milliseconds
)

// SecureRemove removes a file or empty directory securely with configurable options.
func SecureRemove(path string, opts RemoveOptions, log hyperlogger.Logger) error {
	return secureRemovePath(path, opts, log, false)
}

// SecureRemoveAll removes a directory tree securely with configurable options.
func SecureRemoveAll(path string, opts RemoveOptions, log hyperlogger.Logger) error {
	return secureRemovePath(path, opts, log, true)
}

func secureRemovePath(path string, opts RemoveOptions, log hyperlogger.Logger, removeAll bool) error {
	normalized, err := normalizeRemoveOptions(opts)
	if err != nil {
		return err
	}

	resolved, err := resolvePath(path, normalized.BaseDir, normalized.AllowedRoots, normalized.AllowAbsolute)
	if err != nil {
		return err
	}

	err = enforceSymlinkPolicy(resolved.fullPath, resolved.rootPath, resolved.relPath, normalized.AllowSymlinks, true)
	if err != nil {
		return err
	}

	if normalized.AllowSymlinks {
		return removeOnDisk(resolved.fullPath, path, removeAll, normalized.Wipe, log)
	}

	return removeInRoot(resolved, path, log, removeAll, normalized.Wipe)
}

func removeOnDisk(fullPath, originalPath string, removeAll, wipe bool, log hyperlogger.Logger) error {
	if removeAll {
		// #nosec G304 -- path is validated against allowed roots and symlink policy.
		err := os.RemoveAll(fullPath)
		if err != nil {
			return ewrap.Wrap(err, "failed to remove path").
				WithMetadata(pathLabel, originalPath)
		}

		return nil
	}

	if wipe {
		wipeFileOnDisk(fullPath, originalPath, log)
	}

	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	err := os.Remove(fullPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to remove path").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func removeInRoot(
	resolved resolvedPath,
	originalPath string,
	log hyperlogger.Logger,
	removeAll bool,
	wipe bool,
) error {
	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, originalPath)
	}
	defer closeRoot(root, originalPath, log)

	if removeAll {
		err := root.RemoveAll(resolved.relPath)
		if err != nil {
			return ewrap.Wrap(err, "failed to remove path").
				WithMetadata(pathLabel, originalPath)
		}

		return nil
	}

	if wipe {
		wipeFileInRoot(root, resolved.relPath, originalPath, log)
	}

	err = root.Remove(resolved.relPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to remove path").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func wipeFileOnDisk(path, originalPath string, log hyperlogger.Logger) {
	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if log != nil {
			log.WithError(err).Errorf("failed to open file for wipe: %v", originalPath)
		}

		return
	}
	defer closeFile(file, originalPath, log)

	info, err := file.Stat()
	if err != nil {
		if log != nil {
			log.WithError(err).Errorf("failed to stat file for wipe: %v", originalPath)
		}

		return
	}

	if !info.Mode().IsRegular() {
		return
	}

	err = wipeFileContents(file, info.Size())
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to wipe file contents: %v", originalPath)
	}
}

func wipeFileInRoot(root *os.Root, relPath, originalPath string, log hyperlogger.Logger) {
	file, err := root.OpenFile(relPath, os.O_WRONLY, 0)
	if err != nil {
		if log != nil {
			log.WithError(err).Errorf("failed to open file for wipe: %v", originalPath)
		}

		return
	}
	defer closeFile(file, originalPath, log)

	info, err := file.Stat()
	if err != nil {
		if log != nil {
			log.WithError(err).Errorf("failed to stat file for wipe: %v", originalPath)
		}

		return
	}

	if !info.Mode().IsRegular() {
		return
	}

	err = wipeFileContents(file, info.Size())
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to wipe file contents: %v", originalPath)
	}
}

func wipeFileContents(file *os.File, size int64) error {
	if size <= 0 {
		return nil
	}

	_, err := file.Seek(0, 0)
	if err != nil {
		return ewrap.Wrap(err, "failed to seek file", ewrap.WithRetry(maxRetryAttempts, retryDelay))
	}

	buf := make([]byte, readerBufferSize)
	for size > 0 {
		toWrite := min(size, int64(len(buf)))

		bytes, err := file.Write(buf[:toWrite])
		if err != nil {
			return ewrap.Wrap(err, "failed to write file", ewrap.WithRetry(maxRetryAttempts, retryDelay))
		}

		if bytes == 0 {
			return io.ErrShortWrite
		}

		size -= int64(bytes)
	}

	err = file.Sync()
	if err != nil {
		return ewrap.Wrap(err, "failed to sync file", ewrap.WithRetry(maxRetryAttempts, retryDelay))
	}

	return nil
}
