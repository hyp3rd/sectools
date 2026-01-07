package io

import (
	"os"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

// SecureReadDir reads a directory securely with default options.
func SecureReadDir(path string, log hyperlogger.Logger) ([]os.DirEntry, error) {
	return SecureReadDirWithOptions(path, ReadOptions{}, log)
}

// SecureReadDirWithOptions reads a directory securely with configurable options.
func SecureReadDirWithOptions(path string, opts ReadOptions, log hyperlogger.Logger) ([]os.DirEntry, error) {
	normalized, err := normalizeReadOptions(opts)
	if err != nil {
		return nil, err
	}

	resolved, err := resolvePath(path, normalized.BaseDir, normalized.AllowedRoots, normalized.AllowAbsolute)
	if err != nil {
		return nil, err
	}

	err = enforceSymlinkPolicy(resolved.fullPath, resolved.rootPath, resolved.relPath, normalized.AllowSymlinks, false)
	if err != nil {
		return nil, err
	}

	dir, err := openFileHandle(resolved, normalized.AllowSymlinks, log, path)
	if err != nil {
		return nil, err
	}

	defer closeFile(dir, path, log)

	info, err := dir.Stat()
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to stat directory").WithMetadata(pathLabel, path)
	}

	if !info.IsDir() {
		return nil, ErrNotDirectory.WithMetadata(pathLabel, path)
	}

	if normalized.DisallowPerms != 0 && info.Mode().Perm()&normalized.DisallowPerms != 0 {
		return nil, ErrPermissionsNotAllowed.WithMetadata(pathLabel, path)
	}

	err = validateOwnership(info, normalized.OwnerUID, normalized.OwnerGID, path)
	if err != nil {
		return nil, err
	}

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to read directory").WithMetadata(pathLabel, path)
	}

	return entries, nil
}

// SecureMkdirAll creates a directory securely with configurable options.
//
//nolint:revive
func SecureMkdirAll(path string, opts DirOptions, log hyperlogger.Logger) error {
	//  -- cognitive complexity 16 (> max enabled 15), still acceptable.
	normalized, err := normalizeDirOptions(opts)
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

	perm := normalized.DirMode & fileModeMask

	if normalized.AllowSymlinks {
		// #nosec G301 -- path is validated against allowed roots and symlink policy.
		err = os.MkdirAll(resolved.fullPath, perm)
		if err != nil {
			return ewrap.Wrap(err, "failed to create directory").WithMetadata(pathLabel, path)
		}

		if normalized.EnforceMode {
			err = chmodDirOnDisk(resolved.fullPath, normalized.DirMode, log, path)
			if err != nil {
				return err
			}
		}

		return validateDirPermissionsOnDisk(resolved.fullPath, normalized, path)
	}

	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, path)
	}
	defer closeRoot(root, path, log)

	err = root.MkdirAll(resolved.relPath, perm)
	if err != nil {
		return ewrap.Wrap(err, "failed to create directory").WithMetadata(pathLabel, path)
	}

	if normalized.EnforceMode {
		err = chmodDirInRoot(root, resolved.relPath, normalized.DirMode, log, path)
		if err != nil {
			return err
		}
	}

	return validateDirPermissionsInRoot(root, resolved.relPath, normalized, path)
}

func validateDirPermissionsOnDisk(path string, opts DirOptions, originalPath string) error {
	info, err := os.Stat(path)
	if err != nil {
		return ewrap.Wrap(err, "failed to stat directory").WithMetadata(pathLabel, originalPath)
	}

	return validateDirInfo(info, opts, originalPath)
}

func validateDirPermissionsInRoot(root *os.Root, relPath string, opts DirOptions, originalPath string) error {
	info, err := root.Stat(relPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to stat directory").WithMetadata(pathLabel, originalPath)
	}

	return validateDirInfo(info, opts, originalPath)
}

func validateDirInfo(info os.FileInfo, opts DirOptions, originalPath string) error {
	if !info.IsDir() {
		return ErrNotDirectory.WithMetadata(pathLabel, originalPath)
	}

	if opts.DisallowPerms != 0 && info.Mode().Perm()&opts.DisallowPerms != 0 {
		return ErrPermissionsNotAllowed.WithMetadata(pathLabel, originalPath)
	}

	err := validateOwnership(info, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		return err
	}

	return nil
}

func chmodDirOnDisk(path string, mode os.FileMode, log hyperlogger.Logger, originalPath string) error {
	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	dir, err := os.Open(path)
	if err != nil {
		return ewrap.Wrap(err, "failed to open directory").WithMetadata(pathLabel, originalPath)
	}
	defer closeFile(dir, originalPath, log)

	err = dir.Chmod(mode)
	if err != nil {
		return ewrap.Wrap(err, "failed to set directory permissions").WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func chmodDirInRoot(root *os.Root, relPath string, mode os.FileMode, log hyperlogger.Logger, originalPath string) error {
	dir, err := root.Open(relPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open directory").WithMetadata(pathLabel, originalPath)
	}
	defer closeFile(dir, originalPath, log)

	err = dir.Chmod(mode)
	if err != nil {
		return ewrap.Wrap(err, "failed to set directory permissions").WithMetadata(pathLabel, originalPath)
	}

	return nil
}
