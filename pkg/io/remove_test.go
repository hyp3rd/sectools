package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureRemoveDefaultOptions(t *testing.T) {
	_, relPath := createTempFile(t, []byte("remove-me"))

	err := SecureRemove(relPath, SecureRemoveOptions{}, nil)
	require.NoError(t, err)

	_, statErr := os.Stat(filepath.Join(os.TempDir(), relPath))
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
}

func TestSecureRemoveAllDefaultOptions(t *testing.T) {
	dirAbs, dirRel := createTempDir(t)

	err := os.WriteFile(filepath.Join(dirAbs, "nested.txt"), []byte("data"), 0o600)
	require.NoError(t, err)

	err = SecureRemoveAll(dirRel, SecureRemoveOptions{}, nil)
	require.NoError(t, err)

	_, statErr := os.Stat(dirAbs)
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
}

func TestSecureRemoveAbsolutePathRejected(t *testing.T) {
	absPath, _ := createTempFile(t, []byte("abs"))

	err := SecureRemove(absPath, SecureRemoveOptions{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "absolute")
}
