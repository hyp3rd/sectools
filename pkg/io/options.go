package io

import (
	"os"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// SecureReadOptions configures secure read behavior.
type SecureReadOptions struct {
	BaseDir         string
	AllowedRoots    []string
	MaxSizeBytes    int64
	AllowAbsolute   bool
	AllowSymlinks   bool
	AllowNonRegular bool
}

// SecureWriteOptions configures secure write behavior.
type SecureWriteOptions struct {
	BaseDir         string
	AllowedRoots    []string
	MaxSizeBytes    int64
	FileMode        os.FileMode
	CreateExclusive bool
	DisableAtomic   bool
	DisableSync     bool
	AllowAbsolute   bool
	AllowSymlinks   bool
}

func toInternalReadOptions(opts SecureReadOptions) internalio.ReadOptions {
	return internalio.ReadOptions{
		BaseDir:         opts.BaseDir,
		AllowedRoots:    opts.AllowedRoots,
		MaxSizeBytes:    opts.MaxSizeBytes,
		AllowAbsolute:   opts.AllowAbsolute,
		AllowSymlinks:   opts.AllowSymlinks,
		AllowNonRegular: opts.AllowNonRegular,
	}
}

func toInternalWriteOptions(opts SecureWriteOptions) internalio.WriteOptions {
	return internalio.WriteOptions{
		BaseDir:         opts.BaseDir,
		AllowedRoots:    opts.AllowedRoots,
		MaxSizeBytes:    opts.MaxSizeBytes,
		FileMode:        opts.FileMode,
		CreateExclusive: opts.CreateExclusive,
		DisableAtomic:   opts.DisableAtomic,
		DisableSync:     opts.DisableSync,
		AllowAbsolute:   opts.AllowAbsolute,
		AllowSymlinks:   opts.AllowSymlinks,
	}
}
