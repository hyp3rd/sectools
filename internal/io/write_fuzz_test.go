package io

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//nolint:revive
func FuzzSecureWriteFromReader(f *testing.F) {
	f.Add("file.txt", []byte("data"), int64(10), false, false, false)
	f.Add("../escape", []byte("data"), int64(10), false, false, false)
	f.Add("nested/file.txt", []byte("data"), int64(10), false, false, false)
	f.Add("link.txt", []byte("data"), int64(10), true, true, false)
	f.Add("abs.txt", []byte("data"), int64(10), true, false, true)

	f.Fuzz(func(t *testing.T, name string, data []byte, maxSize int64, allowSymlinks, useSymlink, makeAbsolute bool) {
		if len(data) > 2048 {
			data = data[:2048]
		}

		if maxSize > 2048 {
			maxSize = 2048
		} else if maxSize < -1 {
			maxSize = -1
		}

		baseDir := t.TempDir()
		path := name
		safeName := sanitizeFileName(name)

		if safeName == "" {
			safeName = "file"
		}

		if useSymlink {
			targetPath := filepath.Join(baseDir, "target-"+safeName)

			err := os.WriteFile(targetPath, []byte("target"), 0o600)
			if err != nil {
				t.Skipf("failed to create symlink target: %v", err)
			}

			linkName := "link-" + safeName

			linkPath := filepath.Join(baseDir, linkName)

			err = os.Symlink(targetPath, linkPath)
			if err != nil {
				t.Skipf("symlink not supported: %v", err)
			}

			path = linkName
			if makeAbsolute {
				path = linkPath
			}
		} else if makeAbsolute {
			path = filepath.Join(baseDir, safeName)
		}

		opts := WriteOptions{
			BaseDir:       baseDir,
			MaxSizeBytes:  maxSize,
			AllowAbsolute: makeAbsolute,
			AllowSymlinks: allowSymlinks,
		}

		err := SecureWriteFromReader(path, bytes.NewReader(data), opts, nil)
		if err != nil {
			t.Log("failed to write:", err)
		}
	})
}

func sanitizeFileName(input string) string {
	cleaned := strings.Map(func(ch rune) rune {
		if ch == '.' {
			return ch
		}

		if ch == ':' || os.IsPathSeparator(uint8(ch)) {
			return -1
		}

		return ch
	}, input)

	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return ""
	}

	return cleaned
}
