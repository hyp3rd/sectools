package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "directory traversal attempt",
			path:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute path",
			path:    "/etc/hosts",
			wantErr: true,
		},
		{
			name: "valid relative path",
			path: "testfile.txt",
			want: filepath.Join(os.TempDir(), "testfile.txt"),
		},
		{
			name: "nested path",
			path: "folder/subfolder/file.txt",
			want: filepath.Join(os.TempDir(), "folder/subfolder/file.txt"),
		},
		{
			name:    "path with multiple directory traversal",
			path:    "safe/../../../etc/passwd",
			wantErr: true,
		},
		{
			name: "path with special characters",
			path: "test@#$%file.txt",
			want: filepath.Join(os.TempDir(), "test@#$%file.txt"),
		},
		{
			name: "path with spaces",
			path: "my test file.txt",
			want: filepath.Join(os.TempDir(), "my test file.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := SecurePath(tt.path)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecurePathSymlink(t *testing.T) {
	t.Parallel()

	tempDir := os.TempDir()
	validPath := filepath.Join(tempDir, "valid.txt")
	symlinkPath := filepath.Join(tempDir, "symlink.txt")

	err := os.WriteFile(validPath, []byte("test"), 0o644)
	require.NoError(t, err)

	t.Cleanup(func() { _ = os.Remove(validPath) })

	err = os.Symlink("/etc/hosts", symlinkPath)
	if err == nil {
		t.Cleanup(func() { _ = os.Remove(symlinkPath) })

		t.Run("symlink outside temp directory", func(t *testing.T) {
			t.Parallel()

			_, err := SecurePath("symlink.txt")
			assert.Error(t, err)
		})
	}
}
