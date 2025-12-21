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
- Rejects empty paths and any path containing `..`.
- If the path is relative, it is resolved under `os.TempDir()`.
- If the path is absolute, it is only accepted when it already begins with `os.TempDir()`.
- Uses `os.OpenRoot(os.TempDir())` and `root.Open(relPath)` to scope file access to the temp directory.
- If a symlink resolves outside the temp directory, the path is rejected.
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

 data, err := sectools.SecureReadFile(path, nil)
 if err != nil {
  panic(err)
 }

 _ = data
}
```

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

 buf, err := sectools.SecureReadFileWithSecureBuffer(path, nil)
 if err != nil {
  panic(err)
 }
 defer buf.Clear()

 _ = buf.Bytes()
}
```

## internal/memory

`SecureBuffer` is an internal type used by `SecureReadFileWithSecureBuffer`.

Key behaviors:

- Copies input data into an internal byte slice protected by a mutex.
- `Bytes()` returns a copy of the internal data.
- `String()` returns a string copy of the internal data.
- `Clear()` overwrites the buffer (random data then zeros), releases the slice, and clears the finalizer.
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
