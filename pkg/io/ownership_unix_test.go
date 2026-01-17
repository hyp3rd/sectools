//go:build linux || darwin || freebsd || netbsd || openbsd

package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureReadFileOwnershipMatch(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("owned"))

	uid := os.Getuid()
	gid := os.Getgid()

	client, err := NewWithOptions(
		WithOwnerUID(uid),
		WithOwnerGID(gid),
	)
	require.NoError(t, err)

	_, err = client.ReadFile(relPath)
	require.NoError(t, err)
}

func TestSecureReadFileOwnershipMismatch(t *testing.T) {
	t.Parallel()

	_, relPath := createTempFile(t, []byte("owned"))

	uid := os.Getuid()
	badUID := uid + 1

	client, err := NewWithOptions(WithOwnerUID(badUID))
	require.NoError(t, err)

	_, err = client.ReadFile(relPath)
	require.ErrorIs(t, err, ErrOwnershipNotAllowed)
}

func TestSecureWriteFileOwnershipMismatch(t *testing.T) {
	t.Parallel()

	uid := os.Getuid()
	badUID := uid + 1

	filename := filepath.Base(uniqueTempPath(t, "sectools-owner-"))

	client, err := NewWithOptions(
		WithWriteDisableAtomic(true),
		WithOwnerUID(badUID),
	)
	require.NoError(t, err)

	err = client.WriteFile(filename, []byte("data"))
	require.ErrorIs(t, err, ErrOwnershipNotAllowed)

	_, statErr := os.Stat(filepath.Join(os.TempDir(), filename))
	require.True(t, os.IsNotExist(statErr))
}
