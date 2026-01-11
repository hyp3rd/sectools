package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureCopyFileDefaultOptions(t *testing.T) {
	data := []byte("copy-data")
	_, relPath := createTempFile(t, data)

	destName := filepath.Base(uniqueTempPath(t, "sectools-copy-"))

	client := New()
	err := client.CopyFile(relPath, destName)
	require.NoError(t, err)

	destPath := filepath.Join(os.TempDir(), destName)

	t.Cleanup(func() { _ = os.Remove(destPath) })

	readData, err := os.ReadFile(destPath)
	require.NoError(t, err)
	require.Equal(t, data, readData)
}

func TestSecureCopyFileMaxSize(t *testing.T) {
	data := []byte("copy-too-large")
	_, relPath := createTempFile(t, data)

	destName := filepath.Base(uniqueTempPath(t, "sectools-copy-max-"))

	client, err := NewWithOptions(WithWriteMaxSize(3))
	require.NoError(t, err)

	err = client.CopyFile(relPath, destName)
	require.ErrorIs(t, err, ErrFileTooLarge)

	destPath := filepath.Join(os.TempDir(), destName)
	_, statErr := os.Stat(destPath)
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
}

func TestSecureCopyFileVerifyChecksum(t *testing.T) {
	data := []byte("copy-verify")
	_, relPath := createTempFile(t, data)

	destName := filepath.Base(uniqueTempPath(t, "sectools-copy-verify-"))

	client, err := NewWithOptions(WithCopyVerifyChecksum(true))
	require.NoError(t, err)

	err = client.CopyFile(relPath, destName)
	require.NoError(t, err)

	destPath := filepath.Join(os.TempDir(), destName)

	t.Cleanup(func() { _ = os.Remove(destPath) })
}
