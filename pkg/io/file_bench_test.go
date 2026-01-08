package io

import (
	"os"
	"path/filepath"
	"testing"
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

	defer func() { _ = os.Remove(file.Name()) }()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()

		b.Fatalf("failed to write temp data: %v", err)
	}

	if err := file.Close(); err != nil {
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
	if err := file.Close(); err != nil {
		_ = os.Remove(path)

		b.Fatalf("failed to close temp file: %v", err)
	}

	if err := os.Remove(path); err != nil {
		b.Fatalf("failed to remove temp file: %v", err)
	}

	b.Cleanup(func() {
		_ = os.Remove(path)
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
