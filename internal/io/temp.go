package io

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

// SecureTempFile creates a temp file securely with configurable options.
//
//nolint:funlen
func SecureTempFile(prefix string, opts TempOptions, log hyperlogger.Logger) (*os.File, error) {
	err := validateTempPrefix(prefix)
	if err != nil {
		return nil, err
	}

	normalized, err := normalizeTempOptions(opts)
	if err != nil {
		return nil, err
	}

	err = validateExistingDir(normalized.BaseDir, normalized.AllowSymlinks, normalized.OwnerUID, normalized.OwnerGID)
	if err != nil {
		return nil, err
	}

	perm, needsChmod := createPerm(normalized.FileMode)

	if normalized.AllowSymlinks {
		// #nosec G304 -- base dir is validated against allowed roots.
		file, err := os.CreateTemp(normalized.BaseDir, prefix)
		if err != nil {
			return nil, ewrap.Wrap(err, "failed to create temp file").
				WithMetadata(pathLabel, normalized.BaseDir)
		}

		err = applyFileMode(file, normalized.FileMode, needsChmod, true, normalized.EnforceFileMode, file.Name())
		if err != nil {
			closeFile(file, file.Name(), log)

			return nil, err
		}

		err = validateFileOwnership(file, normalized.OwnerUID, normalized.OwnerGID, file.Name())
		if err != nil {
			closeFile(file, file.Name(), log)
			removeFileOnDisk(file.Name(), file.Name(), log)

			return nil, err
		}

		return file, nil
	}

	root, err := os.OpenRoot(normalized.BaseDir)
	if err != nil {
		return nil, ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, normalized.BaseDir)
	}
	defer closeRoot(root, normalized.BaseDir, log)

	file, relName, err := createTempFileInRoot(root, prefix, perm, normalized.BaseDir)
	if err != nil {
		return nil, err
	}

	err = applyFileMode(file, normalized.FileMode, needsChmod, true, normalized.EnforceFileMode, relName)
	if err != nil {
		closeFile(file, relName, log)
		removeFileInRoot(root, relName, relName, log)

		return nil, err
	}

	err = validateFileOwnership(file, normalized.OwnerUID, normalized.OwnerGID, relName)
	if err != nil {
		closeFile(file, relName, log)
		removeFileInRoot(root, relName, relName, log)

		return nil, err
	}

	return file, nil
}

// SecureTempDir creates a temp directory securely with configurable options.
func SecureTempDir(prefix string, opts DirOptions, log hyperlogger.Logger) (string, error) {
	err := validateTempPrefix(prefix)
	if err != nil {
		return "", err
	}

	normalized, err := normalizeDirOptions(opts)
	if err != nil {
		return "", err
	}

	err = validateExistingDir(normalized.BaseDir, normalized.AllowSymlinks, normalized.OwnerUID, normalized.OwnerGID)
	if err != nil {
		return "", err
	}

	if normalized.AllowSymlinks {
		return secureTempDirAllowSymlinks(prefix, normalized, log)
	}

	return secureTempDirInRoot(prefix, normalized, log)
}

func secureTempDirAllowSymlinks(prefix string, opts DirOptions, log hyperlogger.Logger) (string, error) {
	perm := opts.DirMode & fileModeMask

	dir, err := createTempDirOnDisk(opts.BaseDir, prefix, perm)
	if err != nil {
		return "", err
	}

	if opts.EnforceMode {
		err := chmodDirOnDisk(dir, opts.DirMode, log, dir)
		if err != nil {
			removeAllOnDisk(dir, log)

			return "", err
		}
	}

	err = validateDirPermissionsOnDisk(dir, opts, dir)
	if err != nil {
		removeAllOnDisk(dir, log)

		return "", err
	}

	return dir, nil
}

func secureTempDirInRoot(prefix string, opts DirOptions, log hyperlogger.Logger) (string, error) {
	perm := opts.DirMode & fileModeMask

	root, err := os.OpenRoot(opts.BaseDir)
	if err != nil {
		return "", ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, opts.BaseDir)
	}
	defer closeRoot(root, opts.BaseDir, log)

	relName, err := createTempDirInRoot(root, prefix, perm, opts.BaseDir)
	if err != nil {
		return "", err
	}

	if opts.EnforceMode {
		err := chmodDirInRoot(root, relName, opts.DirMode, log, relName)
		if err != nil {
			removeAllInRoot(root, relName, relName, log)

			return "", err
		}
	}

	err = validateDirPermissionsInRoot(root, relName, opts, relName)
	if err != nil {
		removeAllInRoot(root, relName, relName, log)

		return "", err
	}

	return filepath.Join(opts.BaseDir, relName), nil
}

func validateTempPrefix(prefix string) error {
	if strings.ContainsFunc(prefix, func(r rune) bool {
		return os.IsPathSeparator(uint8(r))
	}) {
		return ErrInvalidTempPrefix.WithMetadata(pathLabel, prefix)
	}

	if volume := filepath.VolumeName(prefix); volume != "" {
		return ErrInvalidTempPrefix.WithMetadata(pathLabel, prefix)
	}

	return nil
}

func createTempFileInRoot(root *os.Root, prefix string, perm os.FileMode, originalPath string) (*os.File, string, error) {
	for range tempMaxAttempts {
		name, err := newTempNameWithPrefix(prefix)
		if err != nil {
			return nil, "", err
		}

		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			if os.IsExist(err) {
				continue
			}

			return nil, "", ewrap.Wrap(err, "failed to create temp file").
				WithMetadata(pathLabel, originalPath)
		}

		return file, name, nil
	}

	return nil, "", ewrap.New("failed to create temp file").
		WithMetadata(pathLabel, originalPath)
}

func createTempDirOnDisk(baseDir, prefix string, perm os.FileMode) (string, error) {
	for range tempMaxAttempts {
		name, err := newTempNameWithPrefix(prefix)
		if err != nil {
			return "", err
		}

		dir := filepath.Join(baseDir, name)

		// #nosec G304 -- base dir is validated against allowed roots.
		err = os.Mkdir(dir, perm)
		if err != nil {
			if os.IsExist(err) {
				continue
			}

			return "", ewrap.Wrap(err, "failed to create temp directory").
				WithMetadata(pathLabel, baseDir)
		}

		return dir, nil
	}

	return "", ewrap.New("failed to create temp directory").
		WithMetadata(pathLabel, baseDir)
}

func createTempDirInRoot(root *os.Root, prefix string, perm os.FileMode, originalPath string) (string, error) {
	for range tempMaxAttempts {
		name, err := newTempNameWithPrefix(prefix)
		if err != nil {
			return "", err
		}

		err = root.Mkdir(name, perm)
		if err != nil {
			if os.IsExist(err) {
				continue
			}

			return "", ewrap.Wrap(err, "failed to create temp directory").
				WithMetadata(pathLabel, originalPath)
		}

		return name, nil
	}

	return "", ewrap.New("failed to create temp directory").
		WithMetadata(pathLabel, originalPath)
}

func newTempNameWithPrefix(prefix string) (string, error) {
	buf := make([]byte, tempRandBytes)

	_, err := rand.Read(buf)
	if err != nil {
		return "", ewrap.Wrap(err, "failed to generate temp name")
	}

	if prefix == "" {
		prefix = tempFilePrefix
	}

	return prefix + hex.EncodeToString(buf), nil
}

func validateExistingDir(path string, allowSymlinks bool, ownerUID, ownerGID *int) error {
	// #nosec G304 -- base dir is validated against allowed roots.
	info, err := os.Lstat(path)
	if err != nil {
		return ewrap.Wrap(err, "failed to stat base directory").WithMetadata(pathLabel, path)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		if !allowSymlinks {
			return ErrSymlinkNotAllowed.WithMetadata(pathLabel, path)
		}

		// #nosec G304 -- base dir is validated against allowed roots.
		info, err = os.Stat(path)
		if err != nil {
			return ewrap.Wrap(err, "failed to stat base directory").WithMetadata(pathLabel, path)
		}
	}

	if !info.IsDir() {
		return ErrNotDirectory.WithMetadata(pathLabel, path)
	}

	return validateOwnership(info, ownerUID, ownerGID, path)
}

func removeAllOnDisk(path string, log hyperlogger.Logger) {
	// #nosec G304 -- path is validated against allowed roots.
	err := os.RemoveAll(path)
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to remove path %v", path)
	}
}

func removeAllInRoot(root *os.Root, relPath, originalPath string, log hyperlogger.Logger) {
	if root == nil {
		return
	}

	err := root.RemoveAll(relPath)
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to remove path %v", originalPath)
	}
}
