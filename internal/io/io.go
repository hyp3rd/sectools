// Package io provides secure input/output operations.
package io

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"

	"github.com/hyp3rd/sectools/internal/memory"
)

const pathLabel = "path"

// SecurePath validates and sanitizes a file path, preventing directory traversal and absolute path usage.
// It prepends the system's temp directory to the provided path and returns an error if the path:
// - is empty
// - contains ".."
// - is an absolute path
// - resolves to a symlink outside the temp directory
// Returns a secure, relative path within the system's temp directory or an error if the path is invalid.
func SecurePath(path string, allowedPaths ...string) (string, error) {
	cleanPath, err := cleanPath(path)
	if err != nil {
		return "", ewrap.Wrap(err, "failed to clean path").WithMetadata(pathLabel, path)
	}

	// Check for directory traversal attempts
	if hasDirectoryTraversal(cleanPath) {
		return "", ewrap.New("invalid path contains directory traversal sequence").
			WithMetadata(pathLabel, path)
	}

	if isAllowedPath(cleanPath, allowedPaths...) {
		return cleanPath, nil
	}

	// Check for absolute paths
	isAbsTempAllowed, err := isAbsoluteOrTempAllowed(path, cleanPath)
	if err != nil {
		return "", err
	}

	if isAbsTempAllowed {
		return path, nil
	}

	tempDir := os.TempDir()
	fullPath := filepath.Join(tempDir, cleanPath)

	err = resolveAndValidateSymlink(fullPath, path)
	if err != nil {
		return "", ewrap.Wrap(err, "symlink validation failed").WithMetadata(pathLabel, path)
	}

	return fullPath, nil
}

// SecureReadFile reads a file into memory with additional security precautions.
// It ensures the file path is secure, opens the file, reads its entire contents into a buffer,
// and provides error handling with resource cleanup. If an error occurs during reading,
// the buffer is zeroed out to prevent potential information leakage.
// Returns the file contents as a byte slice or an error if the file cannot be read securely.
//
//nolint:revive,cyclop // (the function complexity is appropriate for its purpose)
func SecureReadFile(path string, log hyperlogger.Logger) ([]byte, error) {
	securePath, err := SecurePath(path)
	if err != nil {
		return nil, ewrap.Wrap(err, "invalid path")
	}

	tempDir := os.TempDir()

	relPath, err := filepath.Rel(tempDir, securePath)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to determine relative path").WithMetadata(pathLabel, path)
	}

	if strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) || relPath == ".." {
		return nil, ewrap.New("path escapes temp directory").WithMetadata(pathLabel, path)
	}

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to open temp root").WithMetadata(pathLabel, path)
	}

	defer func() {
		err = root.Close()
		if err != nil && log != nil {
			log.WithError(err).Errorf("failed to close root for path %v", path)
		}
	}()

	file, err := root.Open(relPath)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to open file").WithMetadata(pathLabel, path)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			// Log the error but don't return it
			if log != nil {
				log.WithError(err).Errorf("failed to close file with path %v", path)
			}
		}
	}()

	// Get file size to allocate exact buffer
	info, err := file.Stat()
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to get file info").WithMetadata(pathLabel, path)
	}

	// Allocate buffer of exact size
	buf := make([]byte, info.Size())

	// Read directly into buffer
	_, err = io.ReadFull(file, buf)
	if err != nil {
		// Clear buffer before returning error
		for i := range buf {
			buf[i] = 0
		}

		return nil, ewrap.Wrap(err, "failed to read file").WithMetadata(pathLabel, path)
	}

	return buf, nil
}

// SecureReadFileWithSecureBuffer reads a file securely and returns its contents as a SecureBuffer.
// This function combines the security features of SecureReadFile with the memory protection of SecureBuffer.
// It ensures the file path is secure, reads the entire file contents, and wraps them in a SecureBuffer
// which will automatically zero out the memory when garbage collected.
// If an error occurs during reading, all buffers are zeroed out to prevent information leakage.
//
// Parameters:
//   - path: Path to the file to be read
//   - log: Logger instance for recording any non-fatal errors
//
// Returns:
//   - Pointer to a SecureBuffer containing the file contents
//   - An error if the file cannot be read securely
func SecureReadFileWithSecureBuffer(path string, log hyperlogger.Logger) (*memory.SecureBuffer, error) {
	data, err := SecureReadFile(path, log)
	if err != nil {
		return nil, err
	}

	// Create a SecureBuffer from the data
	secureBuffer := memory.NewSecureBuffer(data)

	// Zero out the original buffer to minimize exposure of sensitive data
	for i := range data {
		data[i] = 0
	}

	return secureBuffer, nil
}

// cleanPath normalizes the provided path and checks for emptiness.
// Returns the cleaned path or an error if the path is empty.
func cleanPath(path string) (string, error) {
	// Check for empty path
	if path == "" {
		return "", ewrap.New("path cannot be empty")
	}

	// Clean the path to normalize it
	cleanPath := filepath.Clean(path)

	return cleanPath, nil
}

// hasDirectoryTraversal checks if the cleaned path contains any directory traversal sequences ("..").
func hasDirectoryTraversal(cleanPath string) bool {
	return strings.Contains(cleanPath, "..")
}

// isAllowedPath checks if the cleaned path starts with any of the allowed paths.
func isAllowedPath(cleanPath string, allowedPaths ...string) bool {
	for _, allowedPath := range allowedPaths {
		if strings.HasPrefix(cleanPath, allowedPath) {
			return true
		}
	}

	return false
}

// isAbsoluteOrTempAllowed checks if the cleaned path is absolute and if so, whether it is within the system's temp directory.
func isAbsoluteOrTempAllowed(path, cleanPath string) (bool, error) {
	if filepath.IsAbs(cleanPath) {
		tempDir := os.TempDir()
		if strings.HasPrefix(path, tempDir) {
			return true, nil
		}

		return false, ewrap.New("absolute paths are not allowed").WithMetadata(pathLabel, path)
	}

	return false, nil
}

// resolveAndValidateSymlink resolves symlinks in the full path and ensures
// that the resolved path remains within the system's temp directory.
func resolveAndValidateSymlink(fullPath, originalPath string) error {
	resolvedPath, err := filepath.EvalSymlinks(fullPath)
	if err == nil { // Only check if the path exists and can be resolved
		// Ensure the resolved path is still within the temp directory
		tempDir := os.TempDir()
		if !strings.HasPrefix(resolvedPath, tempDir) {
			return ewrap.New("path resolves to location outside of temp directory").
				WithMetadata(pathLabel, originalPath)
		}
	}

	return nil
}
