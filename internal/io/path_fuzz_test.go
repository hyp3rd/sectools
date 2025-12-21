package io

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func FuzzCleanRelativePath(f *testing.F) {
	seeds := []string{
		"",
		".",
		"test.txt",
		"folder/sub/file.txt",
		"../etc/passwd",
		"folder/../file.txt",
		"folder//file.txt",
		"/etc/hosts",
		"\\windows\\system32",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		cleaned, err := cleanRelativePath(input)
		if err != nil {
			return
		}

		if cleaned == "." || cleaned == "" {
			t.Fatalf("unexpected cleaned path: %q", cleaned)
		}

		if filepath.IsAbs(cleaned) {
			t.Fatalf("unexpected absolute cleaned path: %q", cleaned)
		}

		if hasTraversalSegments(cleaned) {
			t.Fatalf("unexpected traversal in cleaned path: %q", cleaned)
		}

		if !fs.ValidPath(filepath.ToSlash(cleaned)) {
			t.Fatalf("cleaned path is not valid: %q", cleaned)
		}
	})
}

func FuzzResolvePath(f *testing.F) {
	seeds := []string{
		"file.txt",
		"nested/file.txt",
		"../escape",
		"/etc/hosts",
		".",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	baseDir := os.TempDir()
	roots := []string{baseDir}

	f.Fuzz(func(t *testing.T, input string) {
		resolved, err := resolvePath(input, baseDir, roots, false)
		if err != nil {
			return
		}

		if filepath.IsAbs(input) {
			t.Fatalf("absolute input should be rejected: %q", input)
		}

		if resolved.rootPath != baseDir {
			t.Fatalf("unexpected root path: %q", resolved.rootPath)
		}

		if resolved.relPath == "" || resolved.relPath == "." {
			t.Fatalf("unexpected rel path: %q", resolved.relPath)
		}

		ok, err := isWithinRoot(resolved.fullPath, resolved.rootPath)
		if err != nil || !ok {
			t.Fatalf("resolved path not within root: %q", resolved.fullPath)
		}
	})
}
