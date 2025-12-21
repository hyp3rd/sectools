# Usage

This document describes the public API and key behaviors of sectools. It is based on the current code in `pkg/` and supporting implementations in `internal/`.

## Packages

- `pkg/io`: secure file read helpers.
- `pkg/converters`: safe numeric conversions.
- `internal/io`, `internal/memory`: implementation details; not part of the public API contract.

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
- Uses `os.OpenRoot(os.TempDir())` and `root.Open(relPath)` to scope file access to the temp directory.
- When symlinks are allowed, paths that resolve outside the allowed root are rejected.
- Reads the file into a byte slice sized to the file, using `io.ReadFull`.
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
- `AllowAbsolute`: defaults to false.
- `AllowSymlinks`: defaults to false.

## internal/memory

`SecureBuffer` is an internal type used by `SecureReadFileWithSecureBuffer`.

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
