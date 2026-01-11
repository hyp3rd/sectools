# sectools

[![lint](https://github.com/hyp3rd/sectools/actions/workflows/lint.yml/badge.svg)](https://github.com/hyp3rd/sectools/actions/workflows/lint.yml) [![test](https://github.com/hyp3rd/sectools/actions/workflows/test.yml/badge.svg)](https://github.com/hyp3rd/sectools/actions/workflows/test.yml) [![security](https://github.com/hyp3rd/sectools/actions/workflows/security.yml/badge.svg)](https://github.com/hyp3rd/sectools/actions/workflows/security.yml)

Security-focused Go helpers for file I/O, in-memory handling of sensitive data, auth tokens, password hashing, input validation/sanitization, and safe numeric conversions.

## Features

- Secure file reads scoped to the system temp directory
- Secure file writes with atomic replace and permissions
- Secure directory creation/listing with root scoping and symlink checks
- Streaming-safe writes from readers with size caps
- Secure temp file/dir helpers with root scoping
- Secure remove and copy helpers with root scoping
- Symlink checks and root-scoped file access using `os.OpenRoot`
- Secure in-memory buffers with best-effort zeroization
- JWT/PASETO helpers with strict validation and safe defaults
- Password hashing presets for argon2id/bcrypt with rehash detection
- Email and URL validation with optional DNS/redirect/reputation checks
- Random token generation and validation with entropy/length caps
- HTML/Markdown sanitization, SQL/NoSQL input guards, and filename sanitizers
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

 client := sectools.New()
 data, err := client.ReadFile(filepath.Base(path))
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

 client := sectools.New()
 buf, err := client.ReadFileWithSecureBuffer(filepath.Base(path))
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
 client, err := sectools.NewWithOptions(
  sectools.WithWriteSyncDir(true),
 )
 if err != nil {
  panic(err)
 }

 err = client.WriteFile("example.txt", []byte("secret"))
 if err != nil {
  panic(err)
 }
}
```

### JWT sign/verify

```go
package main

import (
 "time"

 "github.com/golang-jwt/jwt/v5"

 sectauth "github.com/hyp3rd/sectools/pkg/auth"
)

func main() {
 signer, err := sectauth.NewJWTSigner(
  sectauth.WithJWTSigningAlgorithm("HS256"),
  sectauth.WithJWTSigningKey([]byte("secret")),
 )
 if err != nil {
  panic(err)
 }

 verifier, err := sectauth.NewJWTVerifier(
  sectauth.WithJWTAllowedAlgorithms("HS256"),
  sectauth.WithJWTVerificationKey([]byte("secret")),
  sectauth.WithJWTIssuer("sectools"),
  sectauth.WithJWTAudience("apps"),
 )
 if err != nil {
  panic(err)
 }

 claims := jwt.RegisteredClaims{
  Issuer:    "sectools",
  Audience:  jwt.ClaimStrings{"apps"},
  ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
 }

 token, err := signer.Sign(claims)
 if err != nil {
  panic(err)
 }

 _ = verifier.Verify(token, &jwt.RegisteredClaims{})
}
```

### Password hashing

```go
package main

import (
 "github.com/hyp3rd/sectools/pkg/password"
)

func main() {
 hasher, err := password.NewArgon2id(password.Argon2idBalanced())
 if err != nil {
  panic(err)
 }

 hash, err := hasher.Hash([]byte("secret"))
 if err != nil {
  panic(err)
 }

 ok, needsRehash, err := hasher.Verify([]byte("secret"), hash)
 if err != nil {
  panic(err)
 }

 _, _ = ok, needsRehash
}
```

### Input validation

```go
package main

import (
 "context"

 "github.com/hyp3rd/sectools/pkg/validate"
)

func main() {
 emailValidator, err := validate.NewEmailValidator(
  validate.WithEmailVerifyDomain(true),
 )
 if err != nil {
  panic(err)
 }

 _, _ = emailValidator.Validate(context.Background(), "user@example.com")

 urlValidator, err := validate.NewURLValidator(
  validate.WithURLCheckRedirects(3),
 )
 if err != nil {
  panic(err)
 }

 _, _ = urlValidator.Validate(context.Background(), "https://example.com")
}
```

### Tokens

```go
package main

import (
 "github.com/hyp3rd/sectools/pkg/tokens"
)

func main() {
 generator, err := tokens.NewGenerator()
 if err != nil {
  panic(err)
 }

 validator, err := tokens.NewValidator()
 if err != nil {
  panic(err)
 }

 token, _ := generator.Generate()
 _, _ = validator.Validate(token)
}
```

### Sanitization

```go
package main

import (
 "github.com/hyp3rd/sectools/pkg/sanitize"
)

func main() {
 htmlSanitizer, err := sanitize.NewHTMLSanitizer()
 if err != nil {
  panic(err)
 }

 safeHTML, _ := htmlSanitizer.Sanitize("<b>hello</b>")

 sqlSanitizer, err := sanitize.NewSQLSanitizer(
  sanitize.WithSQLMode(sanitize.SQLModeIdentifier),
  sanitize.WithSQLAllowQualifiedIdentifiers(true),
 )
 if err != nil {
  panic(err)
 }

 safeIdentifier, _ := sqlSanitizer.Sanitize("public.users")

 detector, err := sanitize.NewNoSQLInjectionDetector()
 if err != nil {
  panic(err)
 }

 _ = detector.Detect(`{"username":{"$ne":null}}`)

 _, _ = safeHTML, safeIdentifier
}
```

## Security and behavior notes

- `ReadFile` only permits relative paths under `os.TempDir()` by default. Use `NewWithOptions` with `WithAllowAbsolute` to allow absolute paths or alternate roots.
- Paths containing `..` are rejected to prevent directory traversal.
- `ReadFile` has no default size cap; use `WithReadMaxSize` when file size is untrusted.
- Symlinks are rejected by default; when allowed, paths that resolve outside the allowed roots are rejected.
- File access is scoped with `os.OpenRoot` on the resolved root when symlinks are disallowed. When symlinks are
  allowed, files are opened via resolved paths after symlink checks. See the Go `os.Root` docs for platform-specific
  caveats.
- `WriteFile` uses atomic replace and fsync by default; set `WithWriteDisableAtomic` or `WithWriteDisableSync` only if you accept durability risks. Set `WithWriteSyncDir` to fsync the parent directory after atomic rename for stronger durability guarantees (may be unsupported on some platforms/filesystems).
- Optional ownership checks are available via `WithOwnerUID`/`WithOwnerGID` on Unix platforms.
- `SecureBuffer` zeroizes memory on `Clear()` and uses a finalizer as a best-effort fallback; call `Clear()` when done.

## Documentation

- Detailed usage and behavior notes: [Usage](docs/usage.md)
- A quick reference for teams using sectools in production: [Security checklist](docs/security-checklist.md)

## Development

### Quick Start

1. Clone and set your module name

    ```bash
    git clone https://github.com/hyp3rd/starter.git my-new-project
    cd my-new-project
    ./setup-project.sh --module github.com/your/module
    ```

1. Install toolchain (core). Proto tools stay optional.

    ```bash
    make prepare-toolchain
    # If you need proto/gRPC/OpenAPI
    PROTO_ENABLED=true make prepare-proto-tools
    ```

1. Run quality gates and sample app

    ```bash
    make lint
    make test
    make run   # serves /health on HOSTNAME:PORT (defaults localhost:8000)
    ```

1. Optional: Docker and Compose

    ```bash
    cp .env.example .env   # shared runtime config for compose/requests
    docker build -t starter-app .
    docker compose up --build
    ```

### Make Targets (high level)

- `prepare-toolchain` — install core tools (gci, gofumpt, golangci-lint, staticcheck, govulncheck, gosec)
- `prepare-proto-tools` — install buf + protoc plugins (optional, controlled by PROTO_ENABLED)
- `init` — run setup-project.sh with current module and install tooling (respects PROTO_ENABLED)
- `lint` — gci, gofumpt, staticcheck, golangci-lint
- `test` / `test-race` / `bench`
- `vet`, `sec`, `proto`, `run`, `run-container`, `update-deps`, `update-toolchain`

## Contribution Notes

- Tests required for changes; run `make lint test` before PRs.
- Suggested branch naming: `feat/<scope>`, `fix/<scope>`, `chore/<scope>`.
- Update docs when altering tooling, Make targets, or setup steps.

Follow the [contributing guidelines](./CONTRIBUTING.md).

### Code of Conduct

Make sure you [observe the Code of Conduct](CODE_OF_CONDUCT.md).

## License

GPL-3.0. See [LICENSE](./LICENSE) for details.
