package io

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureTempFileDefaultOptions(t *testing.T) {
	t.Parallel()

	client := New()
	file, err := client.TempFile("sectools-temp-")
	require.NoError(t, err)
	require.NotNil(t, file)

	t.Cleanup(func() {
		err := os.Remove(file.Name())
		if err != nil {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	})

	require.NoError(t, file.Close())

	require.True(t, strings.HasPrefix(file.Name(), os.TempDir()))
}

func TestSecureTempDirDefaultOptions(t *testing.T) {
	t.Parallel()

	client := New()
	dir, err := client.TempDir("sectools-tempdir-")
	require.NoError(t, err)

	t.Cleanup(func() {
		err = os.RemoveAll(dir)
		require.NoError(t, err)
	})

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	require.True(t, strings.HasPrefix(dir, os.TempDir()))
}

func TestSecureTempFileInvalidPrefix(t *testing.T) {
	t.Parallel()

	client := New()
	_, err := client.TempFile(filepath.Join("bad", "prefix"))
	require.ErrorIs(t, err, ErrInvalidTempPrefix)
}
