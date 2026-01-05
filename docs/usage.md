# Usage

This document describes the public API and key behaviors of sectools. It is based on the current code in `pkg/` and supporting implementations in `internal/`.

## Packages

- `pkg/io`: secure file read/write helpers.
- `pkg/memory`: secure in-memory buffers.
- `pkg/converters`: safe numeric conversions.
- `internal/io`: implementation details; not part of the public API contract.

## pkg/io

### SecureReadFile

```go
func SecureReadFile(file string, log hyperlogger.Logger) ([]byte, error)
```

Behavior:

- Validates the path via `internal/io.SecurePath`.
- Rejects empty paths and traversal segments (`..`).
- If the path is relative, it is resolved under `os.TempDir()`.
- Absolute paths are rejected by default; use `SecureReadFileWithOptions` with `AllowAbsolute` to permit.
- Symlinks are rejected by default; use `SecureReadFileWithOptions` with `AllowSymlinks` to permit.
- Non-regular files are rejected by default.
- Uses `os.OpenRoot` on the resolved root and `root.Open(relPath)` to scope file access to allowed roots when
  symlinks are disallowed.
- When `AllowSymlinks` is true, files are opened via resolved paths after symlink checks and may be subject to
  TOCTOU risks.
- When symlinks are allowed, paths that resolve outside the allowed root are rejected.
- Reads the file into a byte slice sized to the file, using `io.ReadFull`.
- `SecureReadFile` does not set a default size cap; use `SecureReadFileWithMaxSize` or `SecureReadFileWithOptions`
  with `MaxSizeBytes` when file size is untrusted.
- Zeroes the buffer before returning an error on a read failure.
- Close errors are logged only when `log` is non-nil.

Example:

```go
package main

import (
 "os"
 "path/filepath"

 sectools "github.com/hyp3rd/sectools/pkg/io"
)

func main() {
 path := filepath.Join(os.TempDir(), "example.txt")
 _ = os.WriteFile(path, []byte("secret"), 0o600)

 data, err := sectools.SecureReadFile(filepath.Base(path), nil)
 if err != nil {
  panic(err)
 }

 _ = data
}
```

### SecureReadFileWithOptions

```go
func SecureReadFileWithOptions(file string, opts SecureReadOptions, log hyperlogger.Logger) ([]byte, error)
```

Options:

- `BaseDir`: defaults to `os.TempDir()`.
- `AllowedRoots`: optional list of allowed root directories.
- `MaxSizeBytes`: when set, rejects files larger than this size.
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.
- `AllowNonRegular`: defaults to false.
- `DisallowPerms`: when set, rejects files with any of these permission bits.

### SecureReadFileWithMaxSize

```go
func SecureReadFileWithMaxSize(file string, maxBytes int64, log hyperlogger.Logger) ([]byte, error)
```

Behavior:

- Uses the same defaults as `SecureReadFile` while enforcing `MaxSizeBytes = maxBytes`.
- Returns `ErrMaxSizeInvalid` when `maxBytes` is zero or negative.

### SecureOpenFile

```go
func SecureOpenFile(file string, opts SecureReadOptions, log hyperlogger.Logger) (*os.File, error)
```

Opens a file for streaming reads while enforcing the same path validation rules as
`SecureReadFileWithOptions`.

### SecureReadFileWithSecureBuffer

```go
func SecureReadFileWithSecureBuffer(filename string, log hyperlogger.Logger) (*memory.SecureBuffer, error)
```

Behavior:

- Calls `SecureReadFile` and then wraps the data in a `SecureBuffer`.
- The original byte slice is zeroed after the secure buffer is created.
- Call `SecureBuffer.Clear()` when the data is no longer needed.

### SecureReadFileWithSecureBufferOptions

```go
func SecureReadFileWithSecureBufferOptions(filename string, opts SecureReadOptions, log hyperlogger.Logger) (*memory.SecureBuffer, error)
```

Behavior:

- Calls `SecureReadFileWithOptions` and then wraps the data in a `SecureBuffer`.
- The original byte slice is zeroed after the secure buffer is created.
- Call `SecureBuffer.Clear()` when the data is no longer needed.

Example:

```go
package main

import (
 "os"
 "path/filepath"

 sectools "github.com/hyp3rd/sectools/pkg/io"
)

func main() {
 path := filepath.Join(os.TempDir(), "example.txt")
 _ = os.WriteFile(path, []byte("secret"), 0o600)

 buf, err := sectools.SecureReadFileWithSecureBuffer(filepath.Base(path), nil)
 if err != nil {
  panic(err)
 }
 defer buf.Clear()

 _ = buf.Bytes()
}
```

### SecureWriteFile

```go
func SecureWriteFile(file string, data []byte, opts SecureWriteOptions, log hyperlogger.Logger) error
```

Options:

- `BaseDir`: defaults to `os.TempDir()`.
- `AllowedRoots`: optional list of allowed root directories.
- `MaxSizeBytes`: when set, rejects writes larger than this size.
- `FileMode`: defaults to `0o600` when zero.
- `CreateExclusive`: when true, fails if the file already exists.
- `DisableAtomic`: when true, writes directly to the target file (no temp file + rename).
- `DisableSync`: when true, skips fsync for higher throughput at the cost of durability.
- `SyncDir`: when true, fsyncs the parent directory after atomic rename or new-file creation.
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.
- `EnforceFileMode`: when true, applies `FileMode` after creation to override umask reductions.

### SecureWriteFromReader

```go
func SecureWriteFromReader(file string, reader io.Reader, opts SecureWriteOptions, log hyperlogger.Logger) error
```

Behavior:

- Validates the path and enforces the same root/symlink policies as `SecureWriteFile`.
- Streams data from the reader with optional size limiting using `MaxSizeBytes`.
- Uses atomic replace by default; direct writes are available with `DisableAtomic`.

### SecureReadDir

```go
func SecureReadDir(path string, log hyperlogger.Logger) ([]os.DirEntry, error)
```

Behavior:

- Validates the directory path using the same root and symlink rules as file reads.
- Rejects non-directory paths.
- Applies `DisallowPerms` when set.

### SecureReadDirWithOptions

```go
func SecureReadDirWithOptions(path string, opts SecureReadOptions, log hyperlogger.Logger) ([]os.DirEntry, error)
```

### SecureMkdirAll

```go
func SecureMkdirAll(path string, opts SecureDirOptions, log hyperlogger.Logger) error
```

Options:

- `BaseDir`: defaults to `os.TempDir()`.
- `AllowedRoots`: optional list of allowed root directories.
- `DirMode`: defaults to `0o700` when zero.
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.
- `EnforceMode`: when true, applies `DirMode` after creation to override umask reductions.
- `DisallowPerms`: when set, rejects directories with any of these permission bits.

### SecureTempFile

```go
func SecureTempFile(prefix string, opts SecureTempOptions, log hyperlogger.Logger) (*os.File, error)
```

Options:

- `BaseDir`: defaults to `os.TempDir()`.
- `AllowedRoots`: optional list of allowed root directories.
- `FileMode`: defaults to `0o600` when zero.
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.
- `EnforceFileMode`: when true, applies `FileMode` after creation to override umask reductions.

### SecureTempDir

```go
func SecureTempDir(prefix string, opts SecureDirOptions, log hyperlogger.Logger) (string, error)
```

### SecureRemove

```go
func SecureRemove(path string, opts SecureRemoveOptions, log hyperlogger.Logger) error
```

Options:

- `BaseDir`: defaults to `os.TempDir()`.
- `AllowedRoots`: optional list of allowed root directories.
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.

### SecureRemoveAll

```go
func SecureRemoveAll(path string, opts SecureRemoveOptions, log hyperlogger.Logger) error
```

### SecureCopyFile

```go
func SecureCopyFile(src string, dest string, opts SecureCopyOptions, log hyperlogger.Logger) error
```

Options:

- `Read`: `SecureReadOptions` applied to the source file.
- `Write`: `SecureWriteOptions` applied to the destination file.

### Platform caveats

sectools relies on `os.OpenRoot`/`os.Root` to scope file operations to allowed roots. `os.Root` follows symlinks
but rejects those that resolve outside the root. It does not prevent crossing filesystem boundaries, bind mounts,
`/proc`-style special files, or access to Unix device files. On `GOOS=js`, `os.Root` is vulnerable to TOCTOU
symlink checks and cannot guarantee containment. See the Go `os.Root` docs for platform details.

Directory fsync behavior: when `SyncDir` is enabled and `DisableSync` is false, sectools attempts to fsync the parent
directory for durability. Some platforms or filesystems do not support directory fsync; in that case the operation
returns `ErrSyncDirUnsupported`.

## pkg/memory

`SecureBuffer` is a public type for holding sensitive data in memory.
Use `NewSecureBuffer` to wrap a byte slice or `NewSecureBufferFromReader` for bounded reads.

Key behaviors:

- Copies input data into an internal byte slice protected by a mutex.
- `Bytes()` and `BytesCopy()` return a copy of the internal data.
- `String()` and `UnsafeString()` return string copies that cannot be zeroized; prefer `BytesCopy()` for sensitive data.
- `Clear()` overwrites the buffer (random data then zeros), releases the slice, and clears the finalizer.
- `ClearFast()` skips the random overwrite and only zeroes the buffer.
- `ZeroBytes()` zeroes a byte slice in place.
- A finalizer calls `Clear()` as a best-effort fallback; it is not deterministic.

## pkg/converters

### SafeUint64FromInt

```go
func SafeUint64FromInt(value int) (uint64, error)
```

- Returns `ErrNegativeValue` when the input is negative.

### SafeUint64FromInt64

```go
func SafeUint64FromInt64(value int64) (uint64, error)
```

- Returns `ErrNegativeValue` when the input is negative.

### SafeIntFromInt64

```go
func SafeIntFromInt64(value int64) (int, error)
```

- Returns an error if the value overflows the native `int` size on the current platform.

### Generic converters

```go
func ToInt64[T Integer](value T) (int64, error)
func ToInt32[T Integer](value T) (int32, error)
func ToInt[T Integer](value T) (int, error)
func ToUint64[T Integer](value T) (uint64, error)
func ToUint32[T Integer](value T) (uint32, error)
func ToUint[T Integer](value T) (uint, error)
```

- Accepts any integer type, including custom types with integer underlying types.
- Returns `ErrNegativeValue` for negative inputs to unsigned targets.
- Returns `ErrOverflow` when the value does not fit in the target type.

### Additional converters

- `SafeUintFromInt64`
- `SafeUint32FromInt64`
- `SafeUint16FromInt64`
- `SafeUint8FromInt64`
- `SafeIntFromUint64`
- `SafeInt32FromInt64`
- `SafeInt16FromInt64`
- `SafeInt8FromInt64`
- `SafeInt64FromUint64`
- `SafeUint32FromUint64`

Example:

```go
package main

import (
 "fmt"

 "github.com/hyp3rd/sectools/pkg/converters"
)

func main() {
 value, err := converters.SafeUint64FromInt64(42)
 fmt.Println(value, err)
}
```

## Testing and linting

```bash
go test ./...
make lint
```
