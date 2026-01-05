package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureReadDirDefaultOptions(t *testing.T) {
	dirAbs, dirRel := createTempDir(t)

	err := os.WriteFile(filepath.Join(dirAbs, "file.txt"), []byte("data"), 0o600)
	require.NoError(t, err)

	entries, err := SecureReadDir(dirRel, nil)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}

	assert.Contains(t, names, "file.txt")
}

func TestSecureReadDirNotDirectory(t *testing.T) {
	_, relPath := createTempFile(t, []byte("data"))

	_, err := SecureReadDir(relPath, nil)
	require.ErrorIs(t, err, ErrNotDirectory)
}

func TestSecureMkdirAllDefaultOptions(t *testing.T) {
	dirName := filepath.Base(uniqueTempPath(t, "sectools-mkdir-"))

	err := SecureMkdirAll(dirName, SecureDirOptions{}, nil)
	require.NoError(t, err)

	dirPath := filepath.Join(os.TempDir(), dirName)

	t.Cleanup(func() { _ = os.RemoveAll(dirPath) })

	info, err := os.Stat(dirPath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
