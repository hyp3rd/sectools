// Package io provides secure input/output operations.
package io

import (
	"io"
	"os"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"

	"github.com/hyp3rd/sectools/pkg/memory"
)

// SecurePath validates and sanitizes a file path using default read options.
// It returns a resolved path or an error if validation fails.
func SecurePath(path string, allowedRoots ...string) (string, error) {
	opts := ReadOptions{
		AllowedRoots: allowedRoots,
	}

	if len(allowedRoots) > 0 {
		opts.AllowAbsolute = true
	}

	normalized, err := normalizeReadOptions(opts)
	if err != nil {
		return "", err
	}

	resolved, err := resolvePath(path, normalized.BaseDir, normalized.AllowedRoots, normalized.AllowAbsolute)
	if err != nil {
		return "", err
	}

	err = enforceSymlinkPolicy(resolved.fullPath, resolved.rootPath, resolved.relPath, normalized.AllowSymlinks, true)
	if err != nil {
		return "", err
	}

	return resolved.fullPath, nil
}

// SecureReadFile reads a file into memory with default secure options.
// Use SecureReadFileWithOptions for custom behaviors.
func SecureReadFile(path string, log hyperlogger.Logger) ([]byte, error) {
	return SecureReadFileWithOptions(path, ReadOptions{}, log)
}

// SecureReadFileWithOptions reads a file into memory with configurable security options.
func SecureReadFileWithOptions(path string, opts ReadOptions, log hyperlogger.Logger) ([]byte, error) {
	file, info, err := openFileWithOptions(path, opts, log)
	if err != nil {
		return nil, err
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil && log != nil {
			log.WithError(closeErr).Errorf("failed to close file with path %v", path)
		}
	}()

	maxInt := int64(^uint(0) >> 1)
	if info.Size() > maxInt {
		return nil, ErrFileTooLarge.WithMetadata(pathLabel, path)
	}

	buf := make([]byte, int(info.Size()))

	_, err = io.ReadFull(file, buf)
	if err != nil {
		for i := range buf {
			buf[i] = 0
		}

		return nil, ewrap.Wrap(err, "failed to read file").WithMetadata(pathLabel, path)
	}

	return buf, nil
}

// SecureOpenFile opens a file for streaming reads with configurable security options.
func SecureOpenFile(path string, opts ReadOptions, log hyperlogger.Logger) (*os.File, error) {
	file, _, err := openFileWithOptions(path, opts, log)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// SecureReadFileWithSecureBuffer reads a file securely and returns its contents in a SecureBuffer.
func SecureReadFileWithSecureBuffer(path string, log hyperlogger.Logger) (*memory.SecureBuffer, error) {
	return SecureReadFileWithSecureBufferOptions(path, ReadOptions{}, log)
}

// SecureReadFileWithSecureBufferOptions reads a file securely with options and returns its contents in a SecureBuffer.
func SecureReadFileWithSecureBufferOptions(path string, opts ReadOptions, log hyperlogger.Logger) (*memory.SecureBuffer, error) {
	data, err := SecureReadFileWithOptions(path, opts, log)
	if err != nil {
		return nil, err
	}

	secureBuffer := memory.NewSecureBuffer(data)
	memory.ZeroBytes(data)

	return secureBuffer, nil
}

func openFileWithOptions(path string, opts ReadOptions, log hyperlogger.Logger) (*os.File, os.FileInfo, error) {
	normalized, err := normalizeReadOptions(opts)
	if err != nil {
		return nil, nil, err
	}

	resolved, err := resolvePath(path, normalized.BaseDir, normalized.AllowedRoots, normalized.AllowAbsolute)
	if err != nil {
		return nil, nil, err
	}

	err = enforceSymlinkPolicy(resolved.fullPath, resolved.rootPath, resolved.relPath, normalized.AllowSymlinks, false)
	if err != nil {
		return nil, nil, err
	}

	file, err := openFileHandle(resolved, normalized.AllowSymlinks, log, path)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		closeFile(file, path, log)

		return nil, nil, ewrap.Wrap(err, "failed to get file info").WithMetadata(pathLabel, path)
	}

	err = validateFileInfo(info, normalized, path)
	if err != nil {
		closeFile(file, path, log)

		return nil, nil, err
	}

	return file, info, nil
}

func openFileHandle(resolved resolvedPath, allowSymlinks bool, log hyperlogger.Logger, originalPath string) (*os.File, error) {
	if allowSymlinks {
		// #nosec G304 -- path is validated against allowed roots and symlink policy.
		file, err := os.Open(resolved.fullPath)
		if err != nil {
			return nil, ewrap.Wrap(err, "failed to open file").WithMetadata(pathLabel, originalPath)
		}

		return file, nil
	}

	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, originalPath)
	}

	file, err := root.Open(resolved.relPath)
	closeRoot(root, originalPath, log)

	if err != nil {
		return nil, ewrap.Wrap(err, "failed to open file").WithMetadata(pathLabel, originalPath)
	}

	return file, nil
}

func validateFileInfo(info os.FileInfo, opts ReadOptions, path string) error {
	if info.Size() < 0 {
		return ErrInvalidPath.WithMetadata(pathLabel, path)
	}

	if !opts.AllowNonRegular && !info.Mode().IsRegular() {
		return ErrNonRegularFile.WithMetadata(pathLabel, path)
	}

	if opts.MaxSizeBytes > 0 && info.Size() > opts.MaxSizeBytes {
		return ErrFileTooLarge.WithMetadata(pathLabel, path)
	}

	if opts.DisallowPerms != 0 && info.Mode().Perm()&opts.DisallowPerms != 0 {
		return ErrPermissionsNotAllowed.WithMetadata(pathLabel, path)
	}

	return nil
}

func closeFile(file *os.File, path string, log hyperlogger.Logger) {
	if file == nil {
		return
	}

	closeErr := file.Close()
	if closeErr != nil && log != nil {
		log.WithError(closeErr).Errorf("failed to close file with path %v", path)
	}
}

func closeRoot(root *os.Root, path string, log hyperlogger.Logger) {
	if root == nil {
		return
	}

	closeErr := root.Close()
	if closeErr != nil && log != nil {
		log.WithError(closeErr).Errorf("failed to close root for path %v", path)
	}
}
