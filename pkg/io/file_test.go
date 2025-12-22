package io

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureReadFileDefaultOptionsRelativePath(t *testing.T) {
	absPath, relPath := createTempFile(t, []byte("secret"))

	data, err := SecureReadFile(relPath, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)

	_ = absPath
}

func TestSecureOpenFileDefaultOptionsRelativePath(t *testing.T) {
	absPath, relPath := createTempFile(t, []byte("stream"))

	file, err := SecureOpenFile(relPath, SecureReadOptions{}, nil)
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, []byte("stream"), data)

	require.NoError(t, file.Close())
	_ = absPath
}

func TestSecureOpenFileAllowAbsolute(t *testing.T) {
	absPath, _ := createTempFile(t, []byte("stream"))

	file, err := SecureOpenFile(absPath, SecureReadOptions{
		AllowAbsolute: true,
	}, nil)
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, []byte("stream"), data)

	require.NoError(t, file.Close())
}

func TestSecureReadFileDefaultOptionsAbsolutePathRejected(t *testing.T) {
	absPath, _ := createTempFile(t, []byte("secret"))

	_, err := SecureReadFile(absPath, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestSecureReadFileWithOptionsAllowAbsolute(t *testing.T) {
	absPath, _ := createTempFile(t, []byte("secret"))

	data, err := SecureReadFileWithOptions(absPath, SecureReadOptions{
		AllowAbsolute: true,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)
}

func TestSecureReadFileWithOptionsMaxSize(t *testing.T) {
	_, relPath := createTempFile(t, []byte("secret"))

	_, err := SecureReadFileWithOptions(relPath, SecureReadOptions{
		MaxSizeBytes: 3,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum")
}

func TestSecureReadFileWithOptionsSymlinkPolicy(t *testing.T) {
	targetAbs, linkAbs, linkRel := createTempSymlink(t, []byte("secret"))

	_, err := SecureReadFileWithOptions(linkRel, SecureReadOptions{}, nil)
	require.Error(t, err)

	data, err := SecureReadFileWithOptions(linkRel, SecureReadOptions{
		AllowSymlinks: true,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)

	_ = targetAbs
	_ = linkAbs
}

func TestSecureReadFileWithOptionsNonRegular(t *testing.T) {
	dirAbs, dirRel := createTempDir(t)

	_, err := SecureReadFileWithOptions(dirRel, SecureReadOptions{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-regular")

	_ = dirAbs
}

func TestSecureWriteFileDefaultOptions(t *testing.T) {
	filename := filepath.Base(uniqueTempPath(t, "sectools-write-"))
	data := []byte("write-test")

	err := SecureWriteFile(filename, data, SecureWriteOptions{}, nil)
	require.NoError(t, err)

	defer func() { _ = os.Remove(filepath.Join(os.TempDir(), filename)) }()

	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileDisableAtomic(t *testing.T) {
	filename := filepath.Base(uniqueTempPath(t, "sectools-direct-"))
	data := []byte("direct-write")

	err := SecureWriteFile(filename, data, SecureWriteOptions{
		DisableAtomic: true,
	}, nil)
	require.NoError(t, err)

	defer func() { _ = os.Remove(filepath.Join(os.TempDir(), filename)) }()

	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileDisableSync(t *testing.T) {
	filename := filepath.Base(uniqueTempPath(t, "sectools-nosync-"))
	data := []byte("no-sync")

	err := SecureWriteFile(filename, data, SecureWriteOptions{
		DisableSync: true,
	}, nil)
	require.NoError(t, err)

	defer func() { _ = os.Remove(filepath.Join(os.TempDir(), filename)) }()

	readData, err := os.ReadFile(filepath.Join(os.TempDir(), filename))
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestSecureWriteFileAbsolutePathRejected(t *testing.T) {
	path := uniqueTempPath(t, "sectools-abs-")

	err := SecureWriteFile(path, []byte("data"), SecureWriteOptions{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestSecureWriteFileCreateExclusive(t *testing.T) {
	absPath, relPath := createTempFile(t, []byte("existing"))

	err := SecureWriteFile(relPath, []byte("new"), SecureWriteOptions{
		CreateExclusive: true,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exists")

	_ = absPath
}

func TestSecureWriteFileSymlinkRejected(t *testing.T) {
	_, linkAbs, linkRel := createTempSymlink(t, []byte("secret"))

	err := SecureWriteFile(linkRel, []byte("data"), SecureWriteOptions{}, nil)
	require.Error(t, err)

	_ = linkAbs
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
		_ = os.RemoveAll(dir)
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
		_ = os.Remove(linkAbs)
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
