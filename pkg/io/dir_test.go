package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureReadDirDefaultOptions(t *testing.T) {
	t.Parallel()

	dirAbs, dirRel := createTempDir(t)

	err := os.WriteFile(filepath.Join(dirAbs, "file.txt"), []byte("data"), 0o600)
	require.NoError(t, err)

	client := New()
	entries, err := client.ReadDir(dirRel)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}

	assert.Contains(t, names, "file.txt")
}

func TestSecureReadDirNotDirectory(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("data"))

	client := New()
	_, err := client.ReadDir(relPath)
	require.ErrorIs(t, err, ErrNotDirectory)
}

func TestSecureMkdirAllDefaultOptions(t *testing.T) {
	t.Parallel()

	dirName := filepath.Base(uniqueTempPath(t, "sectools-mkdir-"))

	client := New()
	err := client.MkdirAll(dirName)
	require.NoError(t, err)

	dirPath := filepath.Join(os.TempDir(), dirName)

	t.Cleanup(func() {
		err = os.RemoveAll(dirPath)
		require.NoError(t, err)
	})

	info, err := os.Stat(dirPath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
