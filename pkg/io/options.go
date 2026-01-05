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
	DisallowPerms   os.FileMode
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
	SyncDir         bool
	AllowAbsolute   bool
	AllowSymlinks   bool
	EnforceFileMode bool
}

// SecureDirOptions configures secure directory behavior.
type SecureDirOptions struct {
	BaseDir       string
	AllowedRoots  []string
	DirMode       os.FileMode
	AllowAbsolute bool
	AllowSymlinks bool
	EnforceMode   bool
	DisallowPerms os.FileMode
}

// SecureTempOptions configures secure temp file behavior.
type SecureTempOptions struct {
	BaseDir         string
	AllowedRoots    []string
	FileMode        os.FileMode
	AllowAbsolute   bool
	AllowSymlinks   bool
	EnforceFileMode bool
}

// SecureRemoveOptions configures secure remove behavior.
type SecureRemoveOptions struct {
	BaseDir       string
	AllowedRoots  []string
	AllowAbsolute bool
	AllowSymlinks bool
}

// SecureCopyOptions configures secure copy behavior.
type SecureCopyOptions struct {
	Read  SecureReadOptions
	Write SecureWriteOptions
}

func toInternalReadOptions(opts SecureReadOptions) internalio.ReadOptions {
	return internalio.ReadOptions{
		BaseDir:         opts.BaseDir,
		AllowedRoots:    opts.AllowedRoots,
		MaxSizeBytes:    opts.MaxSizeBytes,
		AllowAbsolute:   opts.AllowAbsolute,
		AllowSymlinks:   opts.AllowSymlinks,
		AllowNonRegular: opts.AllowNonRegular,
		DisallowPerms:   opts.DisallowPerms,
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
		SyncDir:         opts.SyncDir,
		AllowAbsolute:   opts.AllowAbsolute,
		AllowSymlinks:   opts.AllowSymlinks,
		EnforceFileMode: opts.EnforceFileMode,
	}
}

func toInternalDirOptions(opts SecureDirOptions) internalio.DirOptions {
	return internalio.DirOptions{
		BaseDir:       opts.BaseDir,
		AllowedRoots:  opts.AllowedRoots,
		DirMode:       opts.DirMode,
		AllowAbsolute: opts.AllowAbsolute,
		AllowSymlinks: opts.AllowSymlinks,
		EnforceMode:   opts.EnforceMode,
		DisallowPerms: opts.DisallowPerms,
	}
}

func toInternalTempOptions(opts SecureTempOptions) internalio.TempOptions {
	return internalio.TempOptions{
		BaseDir:         opts.BaseDir,
		AllowedRoots:    opts.AllowedRoots,
		FileMode:        opts.FileMode,
		AllowAbsolute:   opts.AllowAbsolute,
		AllowSymlinks:   opts.AllowSymlinks,
		EnforceFileMode: opts.EnforceFileMode,
	}
}

func toInternalRemoveOptions(opts SecureRemoveOptions) internalio.RemoveOptions {
	return internalio.RemoveOptions{
		BaseDir:       opts.BaseDir,
		AllowedRoots:  opts.AllowedRoots,
		AllowAbsolute: opts.AllowAbsolute,
		AllowSymlinks: opts.AllowSymlinks,
	}
}
