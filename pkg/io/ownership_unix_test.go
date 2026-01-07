//go:build linux || darwin || freebsd || netbsd || openbsd

package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecureReadFileOwnershipMatch(t *testing.T) {
	_, relPath := createTempFile(t, []byte("owned"))

	uid := os.Getuid()
	gid := os.Getgid()

	_, err := SecureReadFileWithOptions(relPath, SecureReadOptions{
		OwnerUID: &uid,
		OwnerGID: &gid,
	}, nil)
	require.NoError(t, err)
}

func TestSecureReadFileOwnershipMismatch(t *testing.T) {
	_, relPath := createTempFile(t, []byte("owned"))

	uid := os.Getuid()
	badUID := uid + 1

	_, err := SecureReadFileWithOptions(relPath, SecureReadOptions{
		OwnerUID: &badUID,
	}, nil)
	require.ErrorIs(t, err, ErrOwnershipNotAllowed)
}

func TestSecureWriteFileOwnershipMismatch(t *testing.T) {
	uid := os.Getuid()
	badUID := uid + 1

	filename := filepath.Base(uniqueTempPath(t, "sectools-owner-"))

	err := SecureWriteFile(filename, []byte("data"), SecureWriteOptions{
		DisableAtomic: true,
		OwnerUID:      &badUID,
	}, nil)
	require.ErrorIs(t, err, ErrOwnershipNotAllowed)

	_, statErr := os.Stat(filepath.Join(os.TempDir(), filename))
	require.True(t, os.IsNotExist(statErr))
}
