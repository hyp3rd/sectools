package io

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

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

	targetExists, err := validateWriteTarget(resolved.fullPath, normalized, path)
	if err != nil {
		return err
	}

	if normalized.AllowSymlinks {
		if normalized.CreateExclusive {
			return writeExclusiveAllowSymlinks(resolved.fullPath, data, normalized, log, path)
		}

		if normalized.DisableAtomic {
			return writeDirectAllowSymlinks(resolved.fullPath, data, normalized, log, path, targetExists)
		}

		return writeAtomicAllowSymlinks(resolved.fullPath, data, normalized, log, path)
	}

	if normalized.CreateExclusive {
		return writeExclusive(resolved, data, normalized, log, path)
	}

	if normalized.DisableAtomic {
		return writeDirect(resolved, data, normalized, log, path, targetExists)
	}

	return writeAtomic(resolved, data, normalized, log, path)
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

func validateWriteTarget(targetPath string, opts WriteOptions, originalPath string) (bool, error) {
	info, err := os.Lstat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, ewrap.Wrap(err, "failed to stat target").
			WithMetadata(pathLabel, originalPath)
	}

	err = validateExistingTarget(info, opts, targetPath, originalPath)
	if err != nil {
		return true, err
	}

	return true, nil
}

func validateExistingTarget(info os.FileInfo, opts WriteOptions, targetPath, originalPath string) error {
	if !info.Mode().IsRegular() {
		return ErrNonRegularFile.WithMetadata(pathLabel, originalPath)
	}

	if info.Mode()&os.ModeSymlink != 0 && !opts.AllowSymlinks {
		return ErrSymlinkNotAllowed.WithMetadata(pathLabel, originalPath)
	}

	if opts.CreateExclusive {
		return ErrFileExists.WithMetadata(pathLabel, originalPath)
	}

	return validateWriteOwnership(info, opts, targetPath, originalPath)
}

func validateWriteOwnership(info os.FileInfo, opts WriteOptions, targetPath, originalPath string) error {
	if opts.OwnerUID == nil && opts.OwnerGID == nil {
		return nil
	}

	if opts.CreateExclusive || opts.DisableAtomic {
		return nil
	}

	checkInfo := info
	if info.Mode()&os.ModeSymlink != 0 && opts.AllowSymlinks {
		targetInfo, statErr := os.Stat(targetPath)
		if statErr == nil {
			checkInfo = targetInfo
		} else if !os.IsNotExist(statErr) {
			return ewrap.Wrap(statErr, "failed to stat target").
				WithMetadata(pathLabel, originalPath)
		}
	}

	return validateOwnership(checkInfo, opts.OwnerUID, opts.OwnerGID, originalPath)
}

func createPerm(mode os.FileMode) (os.FileMode, bool) {
	perm := mode & fileModeMask

	return perm, perm != mode
}

func openExclusiveFile(root *os.Root, relPath string, perm os.FileMode, originalPath string) (*os.File, error) {
	file, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err == nil {
		return file, nil
	}

	if os.IsExist(err) {
		return nil, ErrFileExists.WithMetadata(pathLabel, originalPath)
	}

	return nil, ewrap.Wrap(err, "failed to create file").
		WithMetadata(pathLabel, originalPath)
}

func openDirectFile(root *os.Root, relPath string, perm os.FileMode, targetExists bool) (*os.File, bool, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	if targetExists {
		file, err := root.OpenFile(relPath, flags, perm)
		if err != nil {
			return file, false, ewrap.Wrap(err, "failed to open file for write").
				WithMetadata(pathLabel, relPath)
		}

		return file, false, nil
	}

	file, err := root.OpenFile(relPath, flags|os.O_EXCL, perm)
	if err == nil {
		return file, true, nil
	}

	if !os.IsExist(err) {
		return nil, false, ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, relPath)
	}

	file, err = root.OpenFile(relPath, flags, perm)
	if err != nil {
		return nil, false, ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, relPath)
	}

	return file, false, nil
}

func openDirectFileOnDisk(path string, perm os.FileMode, targetExists bool, originalPath string) (*os.File, bool, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	if targetExists {
		// #nosec G304 -- path is validated against allowed roots and symlink policy.
		file, err := os.OpenFile(path, flags, perm)
		if err != nil {
			return file, false, ewrap.Wrap(err, "failed to open file for write").
				WithMetadata(pathLabel, originalPath)
		}

		return file, false, nil
	}

	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err := os.OpenFile(path, flags|os.O_EXCL, perm)
	if err == nil {
		return file, true, nil
	}

	if !os.IsExist(err) {
		return nil, false, ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, originalPath)
	}

	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err = os.OpenFile(path, flags, perm)
	if err != nil {
		return nil, false, ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, originalPath)
	}

	return file, false, nil
}

func applyFileMode(
	file *os.File,
	mode os.FileMode,
	needsChmod bool,
	created bool,
	enforce bool,
	originalPath string,
) error {
	if !created || (!needsChmod && !enforce) {
		return nil
	}

	err := file.Chmod(mode)
	if err != nil {
		return ewrap.Wrap(err, "failed to set file permissions").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func writeAndSyncFile(
	file *os.File,
	data []byte,
	opts WriteOptions,
	root *os.Root,
	relPath string,
	created bool,
	originalPath string,
) error {
	err := writeAll(file, data)
	if err != nil {
		return ewrap.Wrap(err, "failed to write file").
			WithMetadata(pathLabel, originalPath)
	}

	if opts.DisableSync {
		return nil
	}

	err = file.Sync()
	if err != nil {
		return ewrap.Wrap(err, "failed to sync file").
			WithMetadata(pathLabel, originalPath)
	}

	if opts.SyncDir && created {
		return syncDirInRoot(root, filepath.Dir(relPath), originalPath)
	}

	return nil
}

func newTempName() (string, error) {
	buf := make([]byte, tempRandBytes)

	_, err := rand.Read(buf)
	if err != nil {
		return "", ewrap.Wrap(err, "failed to generate temp file name")
	}

	return tempFilePrefix + hex.EncodeToString(buf), nil
}

func writeExclusiveAllowSymlinks(path string, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	perm, needsChmod := createPerm(opts.FileMode)

	// #nosec G304 -- path is validated against allowed roots and symlink policy.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return ErrFileExists.WithMetadata(pathLabel, originalPath)
		}

		return ewrap.Wrap(err, "failed to create file").
			WithMetadata(pathLabel, originalPath)
	}

	defer closeFile(file, originalPath, log)

	err = applyFileMode(file, opts.FileMode, needsChmod, true, opts.EnforceFileMode, originalPath)
	if err != nil {
		return err
	}

	err = validateFileOwnership(file, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		removeFileOnDisk(path, originalPath, log)

		return err
	}

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

		if opts.SyncDir {
			err = syncDirOnDisk(filepath.Dir(path), originalPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func writeDirectAllowSymlinks(
	path string,
	data []byte,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
	targetExists bool,
) error {
	perm, needsChmod := createPerm(opts.FileMode)

	file, created, err := openDirectFileOnDisk(path, perm, targetExists, originalPath)
	if err != nil {
		return err
	}

	defer closeFile(file, originalPath, log)

	err = applyFileMode(file, opts.FileMode, needsChmod, created, opts.EnforceFileMode, originalPath)
	if err != nil {
		return err
	}

	err = validateFileOwnership(file, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		if created {
			removeFileOnDisk(path, originalPath, log)
		}

		return err
	}

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

		if opts.SyncDir && created {
			err = syncDirOnDisk(filepath.Dir(path), originalPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeAtomicAllowSymlinks writes data to a file atomically, allowing symlink traversal within the allowed roots.
func writeAtomicAllowSymlinks(path string, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	dir := filepath.Dir(path)

	tempFile, cleanup, err := prepareTempFile(dir, originalPath, log)
	if err != nil {
		return err
	}

	success := false
	defer cleanup(&success)

	closed, err := performAtomicWriteOnDisk(tempFile, path, data, opts, log, originalPath)
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
	tempFile, err := os.CreateTemp(dir, tempFilePrefix)
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

func writeExclusive(resolved resolvedPath, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, originalPath)
	}
	defer closeRoot(root, originalPath, log)

	perm, needsChmod := createPerm(opts.FileMode)

	file, err := openExclusiveFile(root, resolved.relPath, perm, originalPath)
	if err != nil {
		return err
	}

	defer closeFile(file, originalPath, log)

	err = applyFileMode(file, opts.FileMode, needsChmod, true, opts.EnforceFileMode, originalPath)
	if err != nil {
		return err
	}

	err = validateFileOwnership(file, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		removeFileInRoot(root, resolved.relPath, originalPath, log)

		return err
	}

	return writeAndSyncFile(file, data, opts, root, resolved.relPath, true, originalPath)
}

func writeDirect(
	resolved resolvedPath,
	data []byte,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
	targetExists bool,
) error {
	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, originalPath)
	}
	defer closeRoot(root, originalPath, log)

	perm, needsChmod := createPerm(opts.FileMode)

	file, created, err := openDirectFile(root, resolved.relPath, perm, targetExists)
	if err != nil {
		return ewrap.Wrap(err, "failed to open file for write").
			WithMetadata(pathLabel, originalPath)
	}

	defer closeFile(file, originalPath, log)

	err = applyFileMode(file, opts.FileMode, needsChmod, created, opts.EnforceFileMode, originalPath)
	if err != nil {
		return err
	}

	err = validateFileOwnership(file, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		if created {
			removeFileInRoot(root, resolved.relPath, originalPath, log)
		}

		return err
	}

	return writeAndSyncFile(file, data, opts, root, resolved.relPath, created, originalPath)
}

// writeAtomic writes data to a file atomically by writing to a temporary file and renaming it.
func writeAtomic(resolved resolvedPath, data []byte, opts WriteOptions, log hyperlogger.Logger, originalPath string) error {
	root, err := os.OpenRoot(resolved.rootPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open root").WithMetadata(pathLabel, originalPath)
	}
	defer closeRoot(root, originalPath, log)

	dirRel := filepath.Dir(resolved.relPath)

	tempFile, tempRel, cleanup, err := prepareTempFileInRoot(root, dirRel, originalPath, log)
	if err != nil {
		return err
	}

	tempFull := filepath.Join(resolved.rootPath, tempRel)

	success := false
	defer cleanup(&success)

	closed, err := performAtomicWrite(tempFile, root, tempRel, resolved.relPath, data, opts, log, originalPath)
	if err != nil {
		if !closed {
			closeFile(tempFile, tempFull, log)
		}

		return err
	}

	success = true

	return nil
}

// prepareTempFileInRoot creates a temporary file in the specified root and directory.
//
//nolint:revive
func prepareTempFileInRoot(
	root *os.Root,
	dirRel string,
	originalPath string,
	log hyperlogger.Logger,
) (*os.File, string, func(*bool), error) {
	for range tempMaxAttempts {
		name, err := newTempName()
		if err != nil {
			return nil, "", nil, err
		}

		relName := filepath.Join(dirRel, name)

		file, err := root.OpenFile(relName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}

			return nil, "", nil, ewrap.Wrap(err, "failed to create temp file").
				WithMetadata(pathLabel, originalPath)
		}

		cleanup := func(success *bool) {
			if success != nil && *success {
				return
			}

			removeErr := root.Remove(relName)
			if removeErr != nil && log != nil {
				log.WithError(removeErr).Errorf("failed to remove temp file for path %v", originalPath)
			}
		}

		return file, relName, cleanup, nil
	}

	return nil, "", nil, ewrap.New("failed to create temp file").
		WithMetadata(pathLabel, originalPath)
}

func performAtomicWrite(
	file *os.File,
	root *os.Root,
	tempRel string,
	targetRel string,
	data []byte,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) (bool, error) {
	err := applyTempPermissions(file, opts.FileMode, opts.OwnerUID, opts.OwnerGID, originalPath)
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

	err = renameTempFile(root, tempRel, targetRel, originalPath)
	if err != nil {
		return true, err
	}

	if opts.SyncDir && !opts.DisableSync {
		err = syncDirInRoot(root, filepath.Dir(targetRel), originalPath)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

func performAtomicWriteOnDisk(
	file *os.File,
	targetPath string,
	data []byte,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) (bool, error) {
	err := applyTempPermissions(file, opts.FileMode, opts.OwnerUID, opts.OwnerGID, originalPath)
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

	err = renameTempFileOnDisk(file.Name(), targetPath, originalPath)
	if err != nil {
		return true, err
	}

	if opts.SyncDir && !opts.DisableSync {
		err = syncDirOnDisk(filepath.Dir(targetPath), originalPath)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

func applyTempPermissions(file *os.File, mode os.FileMode, ownerUID, ownerGID *int, path string) error {
	err := file.Chmod(mode)
	if err != nil {
		return ewrap.Wrap(err, "failed to set temp file permissions").
			WithMetadata(pathLabel, path)
	}

	return validateFileOwnership(file, ownerUID, ownerGID, path)
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

func renameTempFile(root *os.Root, tempRel, targetRel, originalPath string) error {
	err := root.Rename(tempRel, targetRel)
	if err != nil {
		return ewrap.Wrap(err, "failed to replace target file").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func renameTempFileOnDisk(tempName, targetPath, originalPath string) error {
	// #nosec G703 -- paths are derived from previously validated/contained write targets.
	err := os.Rename(tempName, targetPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to replace target file").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func syncDirInRoot(root *os.Root, relDir, originalPath string) error {
	if root == nil {
		return ErrInvalidPath.WithMetadata(pathLabel, originalPath)
	}

	if relDir == "" {
		relDir = rootDirRel
	}

	dir, err := root.Open(relDir)
	if err != nil {
		return ewrap.Wrap(err, "failed to open directory for sync").
			WithMetadata(pathLabel, originalPath)
	}
	defer closeFile(dir, originalPath, nil)

	err = dir.Sync()
	if err != nil {
		if isSyncUnsupported(err) {
			return ErrSyncDirUnsupported.WithMetadata(pathLabel, originalPath)
		}

		return ewrap.Wrap(err, "failed to sync directory").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func syncDirOnDisk(dirPath, originalPath string) error {
	// #nosec G304 -- dirPath is derived from a validated target path scoped to allowed roots.
	dir, err := os.Open(dirPath)
	if err != nil {
		return ewrap.Wrap(err, "failed to open directory for sync").
			WithMetadata(pathLabel, originalPath)
	}
	defer closeFile(dir, originalPath, nil)

	err = dir.Sync()
	if err != nil {
		if isSyncUnsupported(err) {
			return ErrSyncDirUnsupported.WithMetadata(pathLabel, originalPath)
		}

		return ewrap.Wrap(err, "failed to sync directory").
			WithMetadata(pathLabel, originalPath)
	}

	return nil
}

func isSyncUnsupported(err error) bool {
	if runtime.GOOS == osWindows && errors.Is(err, os.ErrPermission) {
		return true
	}

	return errors.Is(err, os.ErrInvalid) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
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
