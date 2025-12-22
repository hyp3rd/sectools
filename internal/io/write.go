package io

import (
	"io"
	"os"
	"path/filepath"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

// SecureWriteFile writes data to a file with configurable security options.
func SecureWriteFile(path string, data []byte, opts WriteOptions, log hyperlogger.Logger) error {
	normalized, err := normalizeWriteOptions(opts)
	if err != nil {
		return err
	}

	err = validateWriteSize(data, normalized, path)
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

	err = validateParentDir(resolved.fullPath)
	if err != nil {
		return err
	}

	err = validateWriteTarget(resolved.fullPath, normalized, path)
	if err != nil {
		return err
	}

	if normalized.CreateExclusive {
		return writeExclusive(resolved.fullPath, data, normalized, log, path)
	}

	if normalized.DisableAtomic {
		return writeDirect(resolved.fullPath, data, normalized, log, path)
	}

	return writeAtomic(resolved.fullPath, data, normalized, log, path)
}

func validateWriteSize(data []byte, opts WriteOptions, path string) error {
	if opts.MaxSizeBytes > 0 && int64(len(data)) > opts.MaxSizeBytes {
		return ErrFileTooLarge.WithMetadata(pathLabel, path)
	}

	return nil
}

func validateParentDir(targetPath string) error {
	parentDir := filepath.Dir(targetPath)

	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		return ewrap.Wrap(err, "failed to stat parent directory").
			WithMetadata(pathLabel, parentDir)
	}

	if !parentInfo.IsDir() {
		return ErrInvalidPath.WithMetadata(pathLabel, parentDir)
	}

	return nil
}

func validateWriteTarget(targetPath string, opts WriteOptions, originalPath string) error {
	info, err := os.Lstat(targetPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return ErrNonRegularFile.WithMetadata(pathLabel, originalPath)
		}

		if info.Mode()&os.ModeSymlink != 0 && !opts.AllowSymlinks {
			return ErrSymlinkNotAllowed.WithMetadata(pathLabel, originalPath)
		}

		if opts.CreateExclusive {
			return ErrFileExists.WithMetadata(pathLabel, originalPath)
		}

		return nil
	}

	if os.IsNotExist(err) {
		return nil
	}

	return ewrap.Wrap(err, "failed to stat target").
		WithMetadata(pathLabel, originalPath)
}

func writeExclusive(path string, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, opts.FileMode)
	if err != nil {
		if os.IsExist(err) {
			return ErrFileExists.WithMetadata(pathLabel, originalPath)
		}

		return ewrap.Wrap(err, "failed to create file").
			WithMetadata(pathLabel, originalPath)
	}

	defer closeFile(file, originalPath, log)

	err = writeAll(file, data)
	if err != nil {
		return ewrap.Wrap(err, "failed to write file").
			WithMetadata(pathLabel, originalPath)
	}

	if !opts.DisableSync {
		err = file.Sync()
		if err != nil {
			return ewrap.Wrap(err, "failed to sync file").
				WithMetadata(pathLabel, originalPath)
		}
	}

	return nil
}

func writeDirect(path string, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, opts.FileMode)
	if err != nil {
		return ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, originalPath)
	}

	defer closeFile(file, originalPath, log)

	err = writeAll(file, data)
	if err != nil {
		return ewrap.Wrap(err, "failed to write file").
			WithMetadata(pathLabel, originalPath)
	}

	if !opts.DisableSync {
		err = file.Sync()
		if err != nil {
			return ewrap.Wrap(err, "failed to sync file").
				WithMetadata(pathLabel, originalPath)
		}
	}

	return nil
}

// writeAtomic writes data to a file atomically by writing to a temporary file and renaming it.
func writeAtomic(path string, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	dir := filepath.Dir(path)

	tempFile, cleanup, err := prepareTempFile(dir, originalPath, log)
	if err != nil {
		return err
	}

	success := false
	defer cleanup(&success)

	closed, err := performAtomicWrite(tempFile, path, data, opts, log, originalPath)
	if err != nil {
		if !closed {
			closeFile(tempFile, tempFile.Name(), log)
		}

		return err
	}

	success = true

	return nil
}

func prepareTempFile(dir, originalPath string, log hyperlogger.Logger) (*os.File, func(*bool), error) {
	tempFile, err := os.CreateTemp(dir, ".sectools-*")
	if err != nil {
		return nil, nil, ewrap.Wrap(err, "failed to create temp file").
			WithMetadata(pathLabel, originalPath)
	}

	tempName := tempFile.Name()
	cleanup := func(success *bool) {
		if success != nil && *success {
			return
		}

		removeErr := os.Remove(tempName)
		if removeErr != nil && log != nil {
			log.WithError(removeErr).Errorf("failed to remove temp file for path %v", originalPath)
		}
	}

	return tempFile, cleanup, nil
}

func performAtomicWrite(
	file *os.File,
	targetPath string,
	data []byte,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) (bool, error) {
	err := applyTempPermissions(file, opts.FileMode, originalPath)
	if err != nil {
		return false, err
	}

	err = writeTempData(file, data, originalPath)
	if err != nil {
		return false, err
	}

	err = syncTempFile(file, opts.DisableSync, originalPath)
	if err != nil {
		return false, err
	}

	err = closeTempFile(file, log, originalPath)
	if err != nil {
		return true, err
	}

	err = renameTempFile(file.Name(), targetPath, originalPath)
	if err != nil {
		return true, err
	}

	return true, nil
}

func applyTempPermissions(file *os.File, mode os.FileMode, path string) error {
	err := file.Chmod(mode)
	if err != nil {
		return ewrap.Wrap(err, "failed to set temp file permissions").
			WithMetadata(pathLabel, path)
	}

	return nil
}

func writeTempData(file *os.File, data []byte, path string) error {
	err := writeAll(file, data)
	if err != nil {
		return ewrap.Wrap(err, "failed to write temp file").
			WithMetadata(pathLabel, path)
	}

	return nil
}

func syncTempFile(file *os.File, disableSync bool, path string) error {
	if disableSync {
		return nil
	}

	err := file.Sync()
	if err != nil {
		return ewrap.Wrap(err, "failed to sync temp file").
			WithMetadata(pathLabel, path)
	}

	return nil
}

func closeTempFile(file *os.File, log hyperlogger.Logger, path string) error {
	err := file.Close()
	if err != nil {
		if log != nil {
			log.WithError(err).Errorf("failed to close temp file for path %v", path)
		}

		return ewrap.Wrap(err, "failed to close temp file").
			WithMetadata(pathLabel, path)
	}

	return nil
}

func renameTempFile(tempName, targetPath, originalPath string) error {
	err := os.Rename(tempName, targetPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to replace target file").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return ewrap.Wrap(err, "failed to write to file")
		}

		if written == 0 {
			return io.ErrShortWrite
		}

		data = data[written:]
	}

	return nil
}
