package io

import "github.com/hyp3rd/ewrap"

var (
	// ErrEmptyPath indicates that a required path argument was empty.
	ErrEmptyPath = ewrap.New("path cannot be empty")
	// ErrInvalidPath indicates that a path failed validation.
	ErrInvalidPath = ewrap.New("invalid path")
	// ErrAbsolutePathNotAllowed indicates absolute paths are disallowed by policy.
	ErrAbsolutePathNotAllowed = ewrap.New("absolute paths are not allowed")
	// ErrPathEscapesRoot indicates the resolved path is outside the allowed roots.
	ErrPathEscapesRoot = ewrap.New("path escapes allowed root")
	// ErrSymlinkNotAllowed indicates a symlink was encountered when disallowed.
	ErrSymlinkNotAllowed = ewrap.New("symlinks are not allowed")
	// ErrFileTooLarge indicates a file exceeds the configured maximum size.
	ErrFileTooLarge = ewrap.New("file exceeds maximum size")
	// ErrNonRegularFile indicates a non-regular file was encountered when disallowed.
	ErrNonRegularFile = ewrap.New("non-regular files are not allowed")
	// ErrInvalidBaseDir indicates the base directory is invalid.
	ErrInvalidBaseDir = ewrap.New("invalid base directory")
	// ErrInvalidAllowedRoots indicates the allowed roots list is invalid.
	ErrInvalidAllowedRoots = ewrap.New("invalid allowed roots")
	// ErrMaxSizeInvalid indicates the configured max size is invalid.
	ErrMaxSizeInvalid = ewrap.New("max size cannot be negative")
	// ErrFileExists indicates a write target already exists when exclusive creation is requested.
	ErrFileExists = ewrap.New("file already exists")
	// ErrSyncDirUnsupported indicates directory sync is not supported on this platform or filesystem.
	ErrSyncDirUnsupported = ewrap.New("directory sync is not supported")
	// ErrNilReader indicates a nil reader was provided.
	ErrNilReader = ewrap.New("reader cannot be nil")
	// ErrNotDirectory indicates the target path is not a directory.
	ErrNotDirectory = ewrap.New("path is not a directory")
	// ErrInvalidPermissions indicates a permission mask was invalid.
	ErrInvalidPermissions = ewrap.New("invalid permissions")
	// ErrPermissionsNotAllowed indicates a path has disallowed permissions.
	ErrPermissionsNotAllowed = ewrap.New("permissions are not allowed")
	// ErrInvalidTempPrefix indicates a temp prefix was invalid.
	ErrInvalidTempPrefix = ewrap.New("invalid temp prefix")
	// ErrChecksumMismatch indicates a checksum verification failure.
	ErrChecksumMismatch = ewrap.New("checksum mismatch")
)
