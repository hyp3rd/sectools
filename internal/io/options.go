package io

import "os"

// ReadOptions configures secure read behavior.
type ReadOptions struct {
	BaseDir         string
	AllowedRoots    []string
	MaxSizeBytes    int64
	AllowAbsolute   bool
	AllowSymlinks   bool
	AllowNonRegular bool
	DisallowPerms   os.FileMode
	OwnerUID        *int
	OwnerGID        *int
}

// WriteOptions configures secure write behavior.
type WriteOptions struct {
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
	OwnerUID        *int
	OwnerGID        *int
}

// DirOptions configures secure directory behavior.
type DirOptions struct {
	BaseDir       string
	AllowedRoots  []string
	DirMode       os.FileMode
	AllowAbsolute bool
	AllowSymlinks bool
	EnforceMode   bool
	DisallowPerms os.FileMode
	OwnerUID      *int
	OwnerGID      *int
}

// TempOptions configures secure temp file behavior.
type TempOptions struct {
	BaseDir         string
	AllowedRoots    []string
	FileMode        os.FileMode
	AllowAbsolute   bool
	AllowSymlinks   bool
	EnforceFileMode bool
	OwnerUID        *int
	OwnerGID        *int
}

// RemoveOptions configures secure remove behavior.
type RemoveOptions struct {
	BaseDir       string
	AllowedRoots  []string
	AllowAbsolute bool
	AllowSymlinks bool
	Wipe          bool
	OwnerUID      *int
	OwnerGID      *int
}
