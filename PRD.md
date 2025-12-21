# PRD: sectools Production-Ready Hardening and Expansion

## Overview

sectools provides security-focused helpers for file I/O, secure in-memory buffers, and safe numeric conversions. This PRD proposes a production-ready hardening pass plus feature expansion, based on current code under `pkg/` and `internal/`.

## Goals

- Make file I/O primitives safe, consistent, and robust across platforms.
- Expand safe numeric conversion coverage with explicit, testable APIs.
- Improve security posture (symlink handling, path validation, size limits).
- Align toolchain and dependencies with current stable releases at release time.
- Raise test coverage and CI confidence for adoption in production systems.

## Non-Goals

- Full key management or cryptographic storage systems.
- Replacing Go standard library APIs outside security-hardening wrappers.
- Backporting to older Go versions than the chosen current stable release.

## Current State: Observed Gaps / Risks

- Path validation uses `strings.Contains(cleanPath, "..")`, which is not path-segment aware and can reject valid names while still leaving edge cases; validation logic is duplicated between `pkg/io` and `internal/io`. (`internal/io/io.go`, `pkg/io/file.go`)
- Absolute path allowance relies on `strings.HasPrefix(path, tempDir)`, which is not boundary-safe; `SecurePath` can accept inputs that only share a prefix with the temp directory and then later fail deeper in the stack. (`internal/io/io.go`)
- `SecureReadFile` allocates based on file size without any upper bound and does not reject non-regular files (device, fifo, dir). (`internal/io/io.go`)
- Symlink checks are best-effort; `EvalSymlinks` is skipped if the path does not exist and there is a TOCTOU window between check and open. (`internal/io/io.go`)
- `SecureBuffer.String()` returns an immutable string copy that cannot be zeroized, which increases the chance of secret persistence in memory. (`internal/memory/secure_buffer.go`)
- Test coverage for `pkg/io` does not assert successful reads or edge cases; there are no fuzz tests for path handling. (`pkg/io/file_test.go`, `internal/io/io_test.go`)
- Toolchain versions are set in multiple files (go.mod, `.project-settings.env`, `Makefile`, CI); the configured Go version must be verified as a supported, current stable release and kept consistent across all sources.

## Proposed Features and Requirements

### 1) Secure File I/O Hardening (High)

#### Functional requirements (IO)

- Add `SecureReadFileWithOptions(path string, opts SecureReadOptions) ([]byte, error)` with:
      - `BaseDir` (default `os.TempDir()`), or `AllowedRoots []string` for multi-root support.
      - `MaxSizeBytes` to cap allocations and prevent OOM (default set in docs; no breaking change to existing `SecureReadFile`).
      - `AllowAbsolute` and `AllowSymlinks` flags, default false.
      - `AllowNonRegular` flag (default false).
- Add `SecureOpenFile(path string, opts SecureReadOptions) (*os.File, error)` for streaming reads with the same path/permission checks.
- Add `SecureWriteFile(path string, data []byte, opts SecureWriteOptions) error`:
      - Enforce permissions (default `0o600`), atomic writes (temp + rename), and path validation.
      - Optional `MaxSizeBytes` and `CreateExclusive` to avoid overwrite race.

#### Security requirements (IO)

- Replace prefix checks with `filepath.Rel`-based containment and OS-aware case handling (use `strings.EqualFold` on Windows).
- Validate path segments rather than `strings.Contains("..")`; prefer `fs.ValidPath` for relative paths.
- If symlinks are disallowed, ensure the final path is not a symlink and avoid TOCTOU by checking after open (e.g., `Lstat` on the opened file via root where possible).
- Reject non-regular files unless explicitly allowed.

### 2) SecureBuffer Hardening (Medium)

#### Functional requirements (SecureBuffer)

- Add `SecureBuffer.BytesCopy()` (or rename existing `Bytes()` to emphasize copy semantics).
- Deprecate or gate `SecureBuffer.String()` in public docs; add `UnsafeString()` if needed with explicit warnings.
- Add `ZeroBytes([]byte)` helper for callers that manage their own buffers.

#### Security requirements (SecureBuffer)

- Document that strings cannot be zeroized in Go; emphasize `BytesCopy()` + `Clear()`.
- Ensure `Clear()` handles large buffers efficiently; allow a `ClearFast()` option that skips random overwrite if explicitly chosen.

### 3) Converters Expansion (High)

#### Functional requirements (Converters)

- Expand safe numeric conversions with clear errors for negative and overflow cases.
- Provide a minimal, explicit set (avoid generics unless it improves clarity):
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
- Standardize errors: `ErrNegativeValue`, `ErrOverflow` (typed/sentinel).

### 4) Toolchain & Dependency Hygiene (High)

- Align `go.mod`, `.project-settings.env`, `Makefile`, and CI to the same Go version.
- Pin to the current stable Go release at implementation time; verify versions before release.
- Keep `actions/*` versions pinned to released majors and review regularly.
- Run `go get -u` + `go mod tidy` as part of release prep.

### 5) Testing, CI, and Quality (High)

- Add unit tests that perform real reads and validate error cases (size limits, non-regular files, symlink policies).
- Add fuzz tests for path normalization and traversal defenses (`go test -fuzz`).
- Add cross-platform CI matrix (linux, macos, windows).
- Add benchmarks for `SecureReadFile` and `SecureBuffer.Clear`.

## Proposed API Sketch (Non-Binding)

```go
type SecureReadOptions struct {
  BaseDir         string
  AllowedRoots    []string
  MaxSizeBytes    int64
  AllowAbsolute   bool
  AllowSymlinks   bool
  AllowNonRegular bool
}

type SecureWriteOptions struct {
  BaseDir         string
  AllowedRoots    []string
  MaxSizeBytes    int64
  FileMode        os.FileMode
  CreateExclusive bool
  AllowAbsolute   bool
  AllowSymlinks   bool
}

func SecureReadFileWithOptions(path string, opts SecureReadOptions, log hyperlogger.Logger) ([]byte, error)
func SecureOpenFile(path string, opts SecureReadOptions, log hyperlogger.Logger) (*os.File, error)
func SecureWriteFile(path string, data []byte, opts SecureWriteOptions, log hyperlogger.Logger) error
```

## Compatibility and Migration

- Existing `SecureReadFile` and `SecureReadFileWithSecureBuffer` remain for compatibility.
- New options-based APIs provide production-safe defaults; document suggested migration.
- Deprecation notice for `SecureBuffer.String()` in docs only (no immediate breaking change).

## Success Metrics

- 90%+ unit test coverage on `pkg/io` and `internal/io` paths.
- Fuzz tests added and running in CI.
- Zero CI failures across OS matrix.
- Documented security guarantees and limitations in `docs/usage.md`.

## Open Questions

- Should `SecureReadFile` adopt a default max size, or remain unlimited?
- Should `SecureBuffer.String()` be removed in a future major version?
- Do we support non-temp roots by default, or keep temp-only and require explicit opt-in?
- Do we expose a generic converter, or keep explicit function set for clarity?

## Milestones

1) Hardening pass: path validation, size limits, non-regular file checks, tests.
1) New options-based APIs + secure write support.
1) Converter expansion + error standardization.
1) CI matrix + fuzzing + documentation updates.
