# Usage

This document describes the public API and key behaviors of sectools. It is based on the current code in `pkg/` and
supporting implementations in `internal/`.

## Packages

- `pkg/io`: secure file read/write helpers.
- `pkg/memory`: secure in-memory buffers.
- `pkg/converters`: safe numeric conversions.
- `internal/io`: implementation details; not part of the public API contract.

## pkg/io

### Client

```go
func New() *Client
func NewWithOptions(opts ...Option) (*Client, error)
```

`New` returns a client with defaults. `NewWithOptions` applies functional options and validates them. It returns an
error when options conflict or are invalid (for example: invalid permission masks, negative size limits, or base
directories not contained in allowed roots).

Common configuration options:

- `WithLogger(log)`
- `WithBaseDir(path)`
- `WithAllowedRoots(roots...)`
- `WithAllowAbsolute(bool)`
- `WithAllowSymlinks(bool)`
- `WithOwnerUID(uid)` / `WithOwnerGID(gid)`
- `WithReadMaxSize(bytes)`
- `WithReadAllowNonRegular(bool)`
- `WithReadDisallowPerms(mask)`
- `WithWriteMaxSize(bytes)`
- `WithWriteFileMode(mode)`
- `WithWriteCreateExclusive(bool)`
- `WithWriteDisableAtomic(bool)`
- `WithWriteDisableSync(bool)`
- `WithWriteSyncDir(bool)`
- `WithWriteEnforceFileMode(bool)`
- `WithDirMode(mode)`
- `WithDirEnforceMode(bool)`
- `WithDirDisallowPerms(mask)`
- `WithTempFileMode(mode)`
- `WithTempEnforceFileMode(bool)`
- `WithRemoveWipe(bool)`
- `WithCopyVerifyChecksum(bool)`

Example:

```go
import sectio "github.com/hyp3rd/sectools/pkg/io"

client, err := sectio.NewWithOptions(
 sectio.WithAllowAbsolute(true),
 sectio.WithReadMaxSize(10<<20),
)
if err != nil {
 panic(err)
}
```

### ReadFile

```go
func (c *Client) ReadFile(file string) ([]byte, error)
```

Behavior:

- Validates the path and enforces root scoping.
- Rejects empty paths and traversal segments (`..`).
- If the path is relative, it is resolved under `os.TempDir()` unless `WithBaseDir`/`WithAllowedRoots` are configured.
- Absolute paths are rejected by default; use `WithAllowAbsolute` to permit.
- Symlinks are rejected by default; use `WithAllowSymlinks` to permit.
- Non-regular files are rejected by default; use `WithReadAllowNonRegular(true)` to permit.
- Uses `os.OpenRoot` on the resolved root and `root.Open(relPath)` to scope file access to allowed roots when
  symlinks are disallowed.
- When `AllowSymlinks` is true, files are opened via resolved paths after symlink checks and may be subject to
  TOCTOU risks.
- When symlinks are allowed, paths that resolve outside the allowed root are rejected.
- Reads the file into a byte slice sized to the file, using `io.ReadFull`.
- Zeroes the buffer before returning an error on a read failure.
- Close errors are logged only when `log` is non-nil.

### OpenFile

```go
func (c *Client) OpenFile(file string) (*os.File, error)
```

Opens a file for streaming reads while enforcing the same path validation rules as `ReadFile`.

### ReadFileWithSecureBuffer

```go
func (c *Client) ReadFileWithSecureBuffer(filename string) (*memory.SecureBuffer, error)
```

Behavior:

- Calls `ReadFile` and then wraps the data in a `SecureBuffer`.
- The original byte slice is zeroed after the secure buffer is created.
- Call `SecureBuffer.Clear()` when the data is no longer needed.

### WriteFile

```go
func (c *Client) WriteFile(file string, data []byte) error
```

Behavior:

- Validates the path and enforces root scoping.
- Streams data to a temp file and atomically replaces the target by default.
- Uses `WithWriteMaxSize` to enforce max size; defaults to no limit.
- Uses `WithWriteCreateExclusive` to fail if the target exists.
- Uses `WithWriteDisableAtomic` to write directly (no temp file).
- Uses `WithWriteDisableSync` to skip fsync for higher throughput at the cost of durability.
- Uses `WithWriteSyncDir` to fsync the parent directory after creation/rename.
- Uses `WithWriteEnforceFileMode` to apply file mode after creation to override umask reductions.

### WriteFromReader

```go
func (c *Client) WriteFromReader(file string, reader io.Reader) error
```

Behavior:

- Validates the path and enforces the same root/symlink policies as `WriteFile`.
- Streams data from the reader with optional size limiting using `WithWriteMaxSize`.
- Uses atomic replace by default; direct writes are available with `WithWriteDisableAtomic`.

### ReadDir

```go
func (c *Client) ReadDir(path string) ([]os.DirEntry, error)
```

Behavior:

- Validates the directory path using the same root and symlink rules as file reads.
- Rejects non-directory paths.
- Applies `WithReadDisallowPerms` when set.

### MkdirAll

```go
func (c *Client) MkdirAll(path string) error
```

Creates a directory securely using the configured directory options.

### TempFile

```go
func (c *Client) TempFile(prefix string) (*os.File, error)
```

Creates a temp file securely using the configured temp file options.

### TempDir

```go
func (c *Client) TempDir(prefix string) (string, error)
```

Creates a temp directory securely using the configured directory options.

### Remove

```go
func (c *Client) Remove(path string) error
```

Removes a file or empty directory securely. Use `WithRemoveWipe(true)` to attempt a best-effort zero overwrite for
regular files before removal. `WithRemoveWipe` is ignored for `RemoveAll`.

### RemoveAll

```go
func (c *Client) RemoveAll(path string) error
```

### CopyFile

```go
func (c *Client) CopyFile(src string, dest string) error
```

Behavior:

- Uses the configured read/write options for source and destination.
- Use `WithCopyVerifyChecksum(true)` to verify source and destination checksums (SHA-256).

### Platform caveats

sectools relies on `os.OpenRoot`/`os.Root` to scope file operations to allowed roots. `os.Root` follows symlinks
but rejects those that resolve outside the root. It does not prevent crossing filesystem boundaries, bind mounts,
`/proc`-style special files, or access to Unix device files. On `GOOS=js`, `os.Root` is vulnerable to TOCTOU
symlink checks and cannot guarantee containment. See the Go `os.Root` docs for platform details.

Directory fsync behavior: when `WithWriteSyncDir(true)` is enabled and `WithWriteDisableSync(false)` is not set,
sectools attempts to fsync the parent directory for durability. Some platforms or filesystems do not support directory
fsync; in that case the operation returns `ErrSyncDirUnsupported`.

Ownership checks (`WithOwnerUID`/`WithOwnerGID`) are supported on Unix platforms. On other platforms they return
`ErrOwnershipUnsupported`.

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
- `Lock()`/`Unlock()` attempt to prevent swapping to disk (best-effort; may return `ErrLockUnsupported`).
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
