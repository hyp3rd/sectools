package io

import internalio "github.com/hyp3rd/sectools/internal/io"

var (
	// ErrEmptyPath indicates that a required path argument was empty.
	ErrEmptyPath = internalio.ErrEmptyPath
	// ErrInvalidPath indicates that a path failed validation.
	ErrInvalidPath = internalio.ErrInvalidPath
	// ErrAbsolutePathNotAllowed indicates absolute paths are disallowed by policy.
	ErrAbsolutePathNotAllowed = internalio.ErrAbsolutePathNotAllowed
	// ErrPathEscapesRoot indicates the resolved path is outside the allowed roots.
	ErrPathEscapesRoot = internalio.ErrPathEscapesRoot
	// ErrSymlinkNotAllowed indicates a symlink was encountered when disallowed.
	ErrSymlinkNotAllowed = internalio.ErrSymlinkNotAllowed
	// ErrFileTooLarge indicates a file exceeds the configured maximum size.
	ErrFileTooLarge = internalio.ErrFileTooLarge
	// ErrNonRegularFile indicates a non-regular file was encountered when disallowed.
	ErrNonRegularFile = internalio.ErrNonRegularFile
	// ErrInvalidBaseDir indicates the base directory is invalid.
	ErrInvalidBaseDir = internalio.ErrInvalidBaseDir
	// ErrInvalidAllowedRoots indicates the allowed roots list is invalid.
	ErrInvalidAllowedRoots = internalio.ErrInvalidAllowedRoots
	// ErrMaxSizeInvalid indicates the configured max size is invalid.
	ErrMaxSizeInvalid = internalio.ErrMaxSizeInvalid
	// ErrFileExists indicates a write target already exists when exclusive creation is requested.
	ErrFileExists = internalio.ErrFileExists
	// ErrSyncDirUnsupported indicates directory sync is not supported on this platform or filesystem.
	ErrSyncDirUnsupported = internalio.ErrSyncDirUnsupported
	// ErrNilReader indicates a nil reader was provided.
	ErrNilReader = internalio.ErrNilReader
	// ErrNotDirectory indicates the target path is not a directory.
	ErrNotDirectory = internalio.ErrNotDirectory
	// ErrInvalidPermissions indicates a permission mask was invalid.
	ErrInvalidPermissions = internalio.ErrInvalidPermissions
	// ErrPermissionsNotAllowed indicates a path has disallowed permissions.
	ErrPermissionsNotAllowed = internalio.ErrPermissionsNotAllowed
	// ErrInvalidOwnership indicates ownership constraints are invalid.
	ErrInvalidOwnership = internalio.ErrInvalidOwnership
	// ErrOwnershipNotAllowed indicates a path has unexpected ownership.
	ErrOwnershipNotAllowed = internalio.ErrOwnershipNotAllowed
	// ErrOwnershipUnsupported indicates ownership checks are not supported on this platform.
	ErrOwnershipUnsupported = internalio.ErrOwnershipUnsupported
	// ErrInvalidTempPrefix indicates a temp prefix was invalid.
	ErrInvalidTempPrefix = internalio.ErrInvalidTempPrefix
	// ErrChecksumMismatch indicates a checksum verification failure.
	ErrChecksumMismatch = internalio.ErrChecksumMismatch
)
