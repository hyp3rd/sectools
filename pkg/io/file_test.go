package io

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureReadFileDefaultOptionsRelativePath(t *testing.T) {
	t.Parallel()

	absPath, relPath := createTempFile(t, []byte("secret"))

	client := New()
	data, err := client.ReadFile(relPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)

	_ = absPath
}

func TestSecureOpenFileDefaultOptionsRelativePath(t *testing.T) {
	t.Parallel()

	absPath, relPath := createTempFile(t, []byte("stream"))

	client := New()
	file, err := client.OpenFile(relPath)
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, []byte("stream"), data)

	require.NoError(t, file.Close())

	_ = absPath
}

func TestSecureOpenFileAllowAbsolute(t *testing.T) {
	t.Parallel()

	absPath, _ := createTempFile(t, []byte("stream"))

	client, err := NewWithOptions(WithAllowAbsolute(true))
	require.NoError(t, err)

	file, err := client.OpenFile(absPath)
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, []byte("stream"), data)

	require.NoError(t, file.Close())
}

func TestSecureReadFileDefaultOptionsAbsolutePathRejected(t *testing.T) {
	t.Parallel()

	absPath, _ := createTempFile(t, []byte("secret"))

	client := New()
	_, err := client.ReadFile(absPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestSecureReadFileWithOptionsAllowAbsolute(t *testing.T) {
	t.Parallel()

	absPath, _ := createTempFile(t, []byte("secret"))

	client, err := NewWithOptions(WithAllowAbsolute(true))
	require.NoError(t, err)

	data, err := client.ReadFile(absPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)
}

func TestSecureReadFileWithOptionsMaxSize(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("secret"))

	client, err := NewWithOptions(WithReadMaxSize(3))
	require.NoError(t, err)

	_, err = client.ReadFile(relPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum")
}

func TestSecureReadFileWithMaxSizeSuccess(t *testing.T) {
	t.Parallel()

	data := []byte("secret")
	_, relPath := createTempFile(t, data)

	client, err := NewWithOptions(WithReadMaxSize(int64(len(data))))
	require.NoError(t, err)

	read, err := client.ReadFile(relPath)
	require.NoError(t, err)
	assert.Equal(t, data, read)
}

func TestSecureReadFileWithMaxSizeTooLarge(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("secret"))

	client, err := NewWithOptions(WithReadMaxSize(3))
	require.NoError(t, err)

	_, err = client.ReadFile(relPath)
	require.ErrorIs(t, err, ErrFileTooLarge)
}

func TestSecureReadFileWithMaxSizeInvalid(t *testing.T) {
	t.Parallel()

	_, err := NewWithOptions(WithReadMaxSize(0))
	require.ErrorIs(t, err, ErrMaxSizeInvalid)
}

func TestSecureReadFileWithOptionsSymlinkPolicy(t *testing.T) {
	t.Parallel()

	targetAbs, linkAbs, linkRel := createTempSymlink(t, []byte("secret"))

	client := New()
	_, err := client.ReadFile(linkRel)
	require.Error(t, err)

	client, err = NewWithOptions(WithAllowSymlinks(true))
	require.NoError(t, err)

	data, err := client.ReadFile(linkRel)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)

	_ = targetAbs
	_ = linkAbs
}

func TestSecureReadFileWithOptionsNonRegular(t *testing.T) {
	t.Parallel()

	dirAbs, dirRel := createTempDir(t)

	client := New()
	_, err := client.ReadFile(dirRel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-regular")

	_ = dirAbs
}

func TestSecureReadFileWithSecureBufferDefaultOptions(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("secret"))

	client := New()
	buf, err := client.ReadFileWithSecureBuffer(relPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), buf.Bytes())

	buf.Clear()
}

func TestSecureReadFileWithSecureBufferOptionsAllowAbsolute(t *testing.T) {
	t.Parallel()

	absPath, _ := createTempFile(t, []byte("secret"))

	client, err := NewWithOptions(WithAllowAbsolute(true))
	require.NoError(t, err)

	buf, err := client.ReadFileWithSecureBuffer(absPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), buf.Bytes())

	buf.Clear()
}

func TestSecureReadFileWithSecureBufferOptionsMaxSize(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("secret"))

	client, err := NewWithOptions(WithReadMaxSize(3))
	require.NoError(t, err)

	_, err = client.ReadFileWithSecureBuffer(relPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum")
}

func TestSecureWriteFileDefaultOptions(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-write-"))
	data := []byte("write-test")

	client := New()
	err := client.WriteFile(filename, data)
	require.NoError(t, err)

	defer func() {
		err = os.Remove(filepath.Join(os.TempDir(), filename))
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	}()
	//nolint:gosec
	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileDisableAtomic(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-direct-"))
	data := []byte("direct-write")

	client, err := NewWithOptions(WithWriteDisableAtomic(true))
	require.NoError(t, err)

	err = client.WriteFile(filename, data)
	require.NoError(t, err)

	defer func() {
		err = os.Remove(filepath.Join(os.TempDir(), filename))
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	}()
	//nolint:gosec
	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileDisableSync(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-nosync-"))
	data := []byte("no-sync")

	client, err := NewWithOptions(WithWriteDisableSync(true))
	require.NoError(t, err)

	err = client.WriteFile(filename, data)
	require.NoError(t, err)

	defer func() {
		err = os.Remove(filepath.Join(os.TempDir(), filename))
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	}()
	//nolint:gosec
	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileSyncDir(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-syncdir-"))
	data := []byte("sync-dir")

	t.Cleanup(func() {
		err := os.Remove(filepath.Join(os.TempDir(), filename))
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	})

	client, err := NewWithOptions(WithWriteSyncDir(true))
	require.NoError(t, err)

	err = client.WriteFile(filename, data)
	if errors.Is(err, ErrSyncDirUnsupported) {
		t.Skip("directory sync not supported on this platform/filesystem")
	}

	require.NoError(t, err)
	//nolint:gosec
	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileAbsolutePathRejected(t *testing.T) {
	t.Parallel()

	path := uniqueTempPath(t, "sectools-abs-")

	client := New()
	err := client.WriteFile(path, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestSecureWriteFileCreateExclusive(t *testing.T) {
	t.Parallel()

	absPath, relPath := createTempFile(t, []byte("existing"))

	client, err := NewWithOptions(WithWriteCreateExclusive(true))
	require.NoError(t, err)

	err = client.WriteFile(relPath, []byte("new"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exists")

	_ = absPath
}

func TestSecureWriteFileSymlinkRejected(t *testing.T) {
	t.Parallel()

	_, linkAbs, linkRel := createTempSymlink(t, []byte("secret"))

	client := New()
	err := client.WriteFile(linkRel, []byte("data"))
	require.Error(t, err)

	_ = linkAbs
}

func TestSecureWriteFromReaderDefaultOptions(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-reader-"))
	data := "reader-data"

	client := New()
	err := client.WriteFromReader(filename, strings.NewReader(data))
	require.NoError(t, err)

	t.Cleanup(func() {
		err = os.Remove(filepath.Join(os.TempDir(), filename))
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	})
	//nolint:gosec
	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, []byte(data), readData)
}

func TestSecureWriteFromReaderMaxSize(t *testing.T) {
	t.Parallel()

	filename := filepath.Base(uniqueTempPath(t, "sectools-reader-max-"))

	client, err := NewWithOptions(WithWriteMaxSize(3))
	require.NoError(t, err)

	err = client.WriteFromReader(filename, strings.NewReader("secret"))
	require.ErrorIs(t, err, ErrFileTooLarge)

	_, statErr := os.Stat(filepath.Join(os.TempDir(), filename))
	require.Error(t, statErr)
	assert.True(t, os.IsNotExist(statErr))
}

func TestSecureReadFileWithOptionsDisallowPerms(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not reliable on Windows")
	}

	absPath, relPath := createTempFile(t, []byte("secret"))
	//nolint:gosec
	require.NoError(t, os.Chmod(absPath, 0o644))

	client, err := NewWithOptions(WithReadDisallowPerms(0o004))
	require.NoError(t, err)

	_, err = client.ReadFile(relPath)
	require.ErrorIs(t, err, ErrPermissionsNotAllowed)
}

func createTempFile(t *testing.T, data []byte) (string, string) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "sectools-file-*")
	require.NoError(t, err)

	_, err = file.Write(data)
	require.NoError(t, err)

	require.NoError(t, file.Close())

	t.Cleanup(func() {
		_ = os.Remove(file.Name())
	})

	relPath, err := filepath.Rel(os.TempDir(), file.Name())
	require.NoError(t, err)

	return file.Name(), relPath
}

func createTempDir(t *testing.T) (string, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "sectools-dir-*")
	require.NoError(t, err)

	t.Cleanup(func() {
		err = os.RemoveAll(dir)
		require.NoError(t, err)
	})

	relPath, err := filepath.Rel(os.TempDir(), dir)
	require.NoError(t, err)

	return dir, relPath
}

func createTempSymlink(t *testing.T, data []byte) (string, string, string) {
	t.Helper()

	targetAbs, _ := createTempFile(t, data)
	linkAbs := filepath.Join(os.TempDir(), "sectools-link-"+filepath.Base(targetAbs))

	err := os.Symlink(targetAbs, linkAbs)
	if err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	t.Cleanup(func() {
		err = os.Remove(linkAbs)
		require.NoError(t, err)
	})

	return targetAbs, linkAbs, filepath.Base(linkAbs)
}

func uniqueTempPath(t *testing.T, prefix string) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), prefix)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	require.NoError(t, os.Remove(file.Name()))

	return file.Name()
}
