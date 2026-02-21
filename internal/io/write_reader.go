package io

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/hyp3rd/ewrap"
	"github.com/hyp3rd/hyperlogger"
)

const (
	readerBufferSize    = 32 * 1024
	errMsgFailedToWrite = "failed to write data"
)

type limitedWriter struct {
	writer  io.Writer
	max     int64
	written int64
}

func (lw *limitedWriter) Write(data []byte) (int, error) {
	if lw.max <= 0 {
		n, err := lw.writer.Write(data)
		lw.written += int64(n)

		return n, ewrap.Wrap(err, errMsgFailedToWrite)
	}

	remaining := lw.max - lw.written
	if remaining <= 0 {
		return 0, ErrFileTooLarge
	}

	limited := false

	if int64(len(data)) > remaining {
		data = data[:remaining]
		limited = true
	}

	bytesWritten, err := lw.writer.Write(data)
	lw.written += int64(bytesWritten)

	if err != nil {
		return bytesWritten, ewrap.Wrap(err, errMsgFailedToWrite)
	}

	if bytesWritten < len(data) {
		return bytesWritten, io.ErrShortWrite
	}

	if limited {
		return bytesWritten, ErrFileTooLarge
	}

	return bytesWritten, nil
}

// SecureWriteFromReader writes data from a reader to a file with configurable security options.
func SecureWriteFromReader(path string, reader io.Reader, opts WriteOptions, log hyperlogger.Logger) error {
	if reader == nil {
		return ErrNilReader.WithMetadata(pathLabel, path)
	}

	normalized, err := normalizeWriteOptions(opts)
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
			return writeExclusiveFromReaderAllowSymlinks(resolved.fullPath, reader, normalized, log, path)
		}

		if normalized.DisableAtomic {
			return writeDirectFromReaderAllowSymlinks(resolved.fullPath, reader, normalized, log, path, targetExists)
		}

		return writeAtomicFromReaderAllowSymlinks(resolved.fullPath, reader, normalized, log, path)
	}

	if normalized.CreateExclusive {
		return writeExclusiveFromReader(resolved, reader, normalized, log, path)
	}

	if normalized.DisableAtomic {
		return writeDirectFromReader(resolved, reader, normalized, log, path, targetExists)
	}

	return writeAtomicFromReader(resolved, reader, normalized, log, path)
}

func writeExclusiveFromReaderAllowSymlinks(
	path string,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) error {
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

	err = writeAndSyncFileFromReaderOnDisk(file, reader, opts, filepath.Dir(path), true, originalPath)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			removeFileOnDisk(path, originalPath, log)
		}

		return err
	}

	return nil
}

func writeDirectFromReaderAllowSymlinks(
	path string,
	reader io.Reader,
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

	err = writeAndSyncFileFromReaderOnDisk(file, reader, opts, filepath.Dir(path), created, originalPath)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) && created {
			removeFileOnDisk(path, originalPath, log)
		}

		return err
	}

	return nil
}

// writeAtomicFromReaderAllowSymlinks writes data from a reader to a file atomically while allowing symlinks.
func writeAtomicFromReaderAllowSymlinks(
	path string,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) error {
	dir := filepath.Dir(path)

	tempFile, cleanup, err := prepareTempFile(dir, originalPath, log)
	if err != nil {
		return err
	}

	success := false
	defer cleanup(&success)

	closed, err := performAtomicWriteFromReaderOnDisk(tempFile, path, reader, opts, log, originalPath)
	if err != nil {
		if !closed {
			closeFile(tempFile, tempFile.Name(), log)
		}

		return err
	}

	success = true

	return nil
}

func writeExclusiveFromReader(
	resolved resolvedPath,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) error {
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

	err = writeAndSyncFileFromReader(file, reader, opts, root, resolved.relPath, true, originalPath)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			removeFileInRoot(root, resolved.relPath, originalPath, log)
		}

		return err
	}

	return nil
}

func writeDirectFromReader(
	resolved resolvedPath,
	reader io.Reader,
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

	err = writeAndSyncFileFromReader(file, reader, opts, root, resolved.relPath, created, originalPath)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) && created {
			removeFileInRoot(root, resolved.relPath, originalPath, log)
		}

		return err
	}

	return nil
}

// writeAtomicFromReader writes data from a reader to a file atomically.
func writeAtomicFromReader(
	resolved resolvedPath,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) error {
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

	closed, err := performAtomicWriteFromReader(tempFile, root, tempRel, resolved.relPath, reader, opts, log, originalPath)
	if err != nil {
		if !closed {
			closeFile(tempFile, tempFull, log)
		}

		return err
	}

	success = true

	return nil
}

func performAtomicWriteFromReader(
	file *os.File,
	root *os.Root,
	tempRel string,
	targetRel string,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) (bool, error) {
	err := applyTempPermissions(file, opts.FileMode, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		return false, err
	}

	err = writeTempDataFromReader(file, reader, opts.MaxSizeBytes, originalPath)
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

func performAtomicWriteFromReaderOnDisk(
	file *os.File,
	targetPath string,
	reader io.Reader,
	opts WriteOptions,
	log hyperlogger.Logger,
	originalPath string,
) (bool, error) {
	err := applyTempPermissions(file, opts.FileMode, opts.OwnerUID, opts.OwnerGID, originalPath)
	if err != nil {
		return false, err
	}

	err = writeTempDataFromReader(file, reader, opts.MaxSizeBytes, originalPath)
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

func writeAndSyncFileFromReader(
	file *os.File,
	reader io.Reader,
	opts WriteOptions,
	root *os.Root,
	relPath string,
	created bool,
	originalPath string,
) error {
	err := writeFromReader(file, reader, opts.MaxSizeBytes)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			return ErrFileTooLarge.WithMetadata(pathLabel, originalPath)
		}

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

func writeAndSyncFileFromReaderOnDisk(
	file *os.File,
	reader io.Reader,
	opts WriteOptions,
	dirPath string,
	created bool,
	originalPath string,
) error {
	err := writeFromReader(file, reader, opts.MaxSizeBytes)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			return ErrFileTooLarge.WithMetadata(pathLabel, originalPath)
		}

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
		return syncDirOnDisk(dirPath, originalPath)
	}

	return nil
}

func writeTempDataFromReader(file *os.File, reader io.Reader, maxBytes int64, path string) error {
	err := writeFromReader(file, reader, maxBytes)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			return ErrFileTooLarge.WithMetadata(pathLabel, path)
		}

		return ewrap.Wrap(err, "failed to write temp file").
			WithMetadata(pathLabel, path)
	}

	return nil
}

func writeFromReader(file *os.File, reader io.Reader, maxBytes int64) error {
	if maxBytes <= 0 {
		_, err := io.CopyBuffer(file, reader, make([]byte, readerBufferSize))
		if err != nil {
			return ewrap.Wrap(err, errMsgFailedToWrite)
		}
	}

	limited := &limitedWriter{writer: file, max: maxBytes}

	_, err := io.CopyBuffer(limited, reader, make([]byte, readerBufferSize))
	if err != nil {
		return ewrap.Wrap(err, errMsgFailedToWrite)
	}

	return nil
}

func removeFileOnDisk(path, originalPath string, log hyperlogger.Logger) {
	// #nosec G304,G703 -- path is validated against allowed roots and symlink policy.
	err := os.Remove(path)
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to remove file for path %v", originalPath)
	}
}

func removeFileInRoot(root *os.Root, relPath, originalPath string, log hyperlogger.Logger) {
	if root == nil {
		return
	}

	err := root.Remove(relPath)
	if err != nil && log != nil {
		log.WithError(err).Errorf("failed to remove file for path %v", originalPath)
	}
}
