# sectools

Security-focused Go helpers for file I/O, in-memory handling of sensitive data, and safe numeric conversions.

## Features

- Secure file reads scoped to the system temp directory
- Secure file writes with atomic replace and permissions
- Symlink checks and root-scoped file access using `os.OpenRoot`
- Secure in-memory buffers with best-effort zeroization
- Safe integer conversion helpers with overflow/negative guards

## Requirements

- Go 1.25.5+ (see `go.mod`)

## Installation

```bash
go get github.com/hyp3rd/sectools
```

## Usage

### Secure file read

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

### Secure buffer

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

### Safe integer conversions

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

### Secure file write

```go
package main

import (
 sectools "github.com/hyp3rd/sectools/pkg/io"
)

func main() {
 err := sectools.SecureWriteFile("example.txt", []byte("secret"), sectools.SecureWriteOptions{
  DisableAtomic: false,
  DisableSync:   false,
 }, nil)
 if err != nil {
  panic(err)
 }
}
```

## Security and behavior notes

- `SecureReadFile` only permits relative paths under `os.TempDir()` by default. Use `SecureReadFileWithOptions` to allow absolute paths or alternate roots.
- Paths containing `..` are rejected to prevent directory traversal.
- Symlinks are rejected by default; when allowed, paths that resolve outside the allowed roots are rejected.
- File access is scoped with `os.OpenRoot(os.TempDir())`. See the Go `os.Root` docs for platform-specific caveats.
- `SecureWriteFile` uses atomic replace and fsync by default; set `DisableAtomic` or `DisableSync` only if you accept durability risks.
- `SecureBuffer` zeroizes memory on `Clear()` and uses a finalizer as a best-effort fallback; call `Clear()` when done.

## Documentation

- Detailed usage and behavior notes: `docs/usage.md`

## Development

```bash
make test
make lint
make sec
```

## Contributing

See `CONTRIBUTING.md` for guidelines.

## Code of Conduct

See `CODE_OF_CONDUCT.md`.

## License

GPL-3.0. See `LICENSE` for details.
