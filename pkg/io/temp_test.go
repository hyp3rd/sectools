package io

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureTempFileDefaultOptions(t *testing.T) {
	file, err := SecureTempFile("sectools-temp-", SecureTempOptions{}, nil)
	require.NoError(t, err)
	require.NotNil(t, file)

	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	require.NoError(t, file.Close())

	require.True(t, strings.HasPrefix(file.Name(), os.TempDir()))
}

func TestSecureTempDirDefaultOptions(t *testing.T) {
	dir, err := SecureTempDir("sectools-tempdir-", SecureDirOptions{}, nil)
	require.NoError(t, err)

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	require.True(t, strings.HasPrefix(dir, os.TempDir()))
}

func TestSecureTempFileInvalidPrefix(t *testing.T) {
	_, err := SecureTempFile(filepath.Join("bad", "prefix"), SecureTempOptions{}, nil)
	require.ErrorIs(t, err, ErrInvalidTempPrefix)
}
