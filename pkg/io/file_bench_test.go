package io

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkSecureReadFile(b *testing.B) {
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i)
	}

	file, err := os.CreateTemp(b.TempDir(), "sectools-read-bench-*")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}

	defer func() {
		err = os.Remove(file.Name())
		if err != nil {
			b.Fatalf("failed to remove temp file: %v", err)
		}
	}()

	_, err = file.Write(data)
	if err != nil {
		err = file.Close()
		if err != nil {
			b.Fatalf("failed to close temp file: %v", err)
		}

		b.Fatalf("failed to write temp data: %v", err)
	}

	err = file.Close()
	if err != nil {
		b.Fatalf("failed to close temp file: %v", err)
	}

	relPath, err := filepath.Rel(os.TempDir(), file.Name())
	if err != nil {
		b.Fatalf("failed to determine rel path: %v", err)
	}

	b.SetBytes(int64(len(data)))

	client := New()
	for b.Loop() {
		buf, err := client.ReadFile(relPath)
		if err != nil {
			b.Fatalf("failed to read file: %v", err)
		}

		if len(buf) != len(data) {
			b.Fatalf("unexpected read length: %d", len(buf))
		}
	}
}

func BenchmarkSecureWriteFile(b *testing.B) {
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i)
	}

	file, err := os.CreateTemp(b.TempDir(), "sectools-write-bench-*")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}

	path := file.Name()

	err = file.Close()
	if err != nil {
		err = os.Remove(path)
		require.NoError(b, err)

		b.Fatalf("failed to close temp file: %v", err)
	}

	err = os.Remove(path)
	if err != nil {
		b.Fatalf("failed to remove temp file: %v", err)
	}

	b.Cleanup(func() {
		err = os.Remove(path)
		require.NoError(b, err)
	})

	relPath, err := filepath.Rel(os.TempDir(), path)
	if err != nil {
		b.Fatalf("failed to determine rel path: %v", err)
	}

	b.SetBytes(int64(len(data)))

	client := New()
	for b.Loop() {
		err := client.WriteFile(relPath, data)
		if err != nil {
			b.Fatalf("failed to write file: %v", err)
		}
	}
}
