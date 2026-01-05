package io

import (
	"os"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
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
		return removeOnDisk(resolved.fullPath, path, removeAll)
	}

	return removeInRoot(resolved, path, log, removeAll)
}

func removeOnDisk(fullPath, originalPath string, removeAll bool) error {
	if removeAll {
		// #nosec G304 -- path is validated against allowed roots and symlink policy.
		err := os.RemoveAll(fullPath)
		if err != nil {
			return ewrap.Wrap(err, "failed to remove path").
				WithMetadata(pathLabel, originalPath)
		}

		return nil
	}

	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	err := os.Remove(fullPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to remove path").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func removeInRoot(resolved resolvedPath, originalPath string, log hyperlogger.Logger, removeAll bool) error {
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

	err = root.Remove(resolved.relPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to remove path").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}
