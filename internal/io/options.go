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
}
