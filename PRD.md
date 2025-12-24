# PRD: sectools hardening and expansion

## Status

- Draft
- Date: TBD

## Background (current state)

- `pkg/io` exposes secure file read and write helpers with optional logging, plus a `SecureReadFileWithSecureBuffer` helper.
- Default read/write behavior scopes relative paths to `os.TempDir()` and rejects traversal segments.
- Path validation is handled in `internal/io` with normalized base roots, allowed roots, and symlink policy enforcement.
- Reads can be size-limited via `MaxSizeBytes`; writes can be size-limited and use atomic replace + optional fsync.
- `internal/memory` provides `SecureBuffer` with best-effort zeroization and a finalizer.
- `pkg/converters` provides safe integer conversion helpers and generic integer conversions.
- CI includes golangci-lint, staticcheck, govulncheck, gosec, tests, and fuzzing for path helpers.

## Problem statement

The library is already useful, but production-critical consumers need a more complete and safer API surface for
secure file operations and secure in-memory handling. Some gaps and risks are not addressed in the current design.

## Observed gaps and risks

- Public API returns `*internal/memory.SecureBuffer`, which cannot be imported by external users, making the type
  hard to reference or construct outside this module.
- `SecureReadFileWithSecureBuffer` has no options, so callers cannot use custom roots, absolute paths, or size limits
  while still getting a secure buffer.
- Symlink checks are pre-open and rely on filesystem state remaining stable between validation and open/rename. This
  leaves a TOCTOU window on attacker-writable paths.
- Atomic writes sync the file but do not sync the parent directory after rename, which weakens durability guarantees
  on some filesystems.
- `SecureReadFile` reads the full file into memory with no default size cap. This is safe for known-small inputs but
  can lead to memory exhaustion if misused.
- `pkg/io` documentation mentions unrelated functionality and does not fully describe write behaviors in one place.
- Repository hygiene contains large `.gocache` artifacts in-tree, which is risky for supply chain and review.

## Goals

- Provide a public, usable secure-buffer type without exposing `internal/*` in the API.
- Offer secure-buffer reads that support the same options as standard secure reads.
- Reduce exposure to symlink and race-based path escapes as much as the Go standard library allows.
- Strengthen durability semantics for atomic writes with an opt-in directory sync.
- Make secure reads safer by default and more explicit about size limits.
- Improve documentation coverage and accuracy for all exported APIs.

## Non-goals

- Redesign the entire API or introduce breaking changes without a major version bump.
- Replace existing logging dependencies or require a new logging framework.
- Provide a full secure-delete solution (filesystem-dependent and often non-guaranteed).

## Users and use cases

- Service developers reading small secrets from temp or configured roots.
- Operators writing sensitive configuration files atomically with strict permissions.
- Libraries needing safe integer conversions without panics or silent overflow.

## Proposed scope and epics

### P0: Public secure buffer API

- Introduce `pkg/memory` (or `pkg/io` alias) that exports `SecureBuffer`.
- Expose constructors: `NewSecureBuffer([]byte)` and `NewSecureBufferFromReader(io.Reader, maxBytes)`.
- Provide clear docs on `Clear`, `ClearFast`, and string-returning methods.

### P0: Secure buffer read options

- Add `SecureReadFileWithSecureBufferOptions(path, opts, log)` that mirrors `SecureReadFileWithOptions`.
- Ensure it respects `BaseDir`, `AllowedRoots`, `MaxSizeBytes`, and symlink policy.

### P1: Hardened path and symlink handling

- Investigate file-descriptor-relative operations where supported (openat/openat2) to reduce TOCTOU risk.
- Document remaining OS-specific caveats explicitly in `docs/usage.md`.

### P1: Stronger atomic write durability

- Add an option (ex: `SyncDir bool`) to fsync the parent directory after `os.Rename`.
- Clarify durability behavior in docs when `DisableSync` is set.

### P1: Safer defaults and clearer limits

- Provide helper variants such as `SecureReadFileWithMaxSize` to encourage explicit sizing.
- Consider a conservative default `MaxSizeBytes` for `SecureReadFile` or at least highlight the risk in docs.

### P2: Documentation and repo hygiene

- Fix package docs that mention unrelated functionality.
- Expand `docs/usage.md` with write behaviors, symlink policy details, and platform caveats.
- Remove `.gocache` artifacts from the repository and ensure they are ignored.

## Functional requirements

- Public secure buffer type is importable and usable by external packages.
- Secure buffer reads support the full read option set.
- Path operations remain within allowed roots and honor symlink policy.
- Optional directory fsync is available for atomic writes.
- All new APIs have tests and usage examples.

## Non-functional requirements

- No regressions in existing behavior unless gated by new options.
- Maintain compatibility with the current Go version in `go.mod`.
- All changes pass current golangci-lint settings.
- Performance impact is measured for read/write hot paths.

## Security considerations

- Document remaining TOCTOU risks that cannot be fully eliminated with portable Go APIs.
- Keep metadata in errors consistent and avoid leaking sensitive path data in logs by default.
- Ensure secure-buffer APIs do not expose internal memory without explicit opt-in.

## Success metrics

- New secure-buffer APIs adopted by at least one downstream service.
- Added tests cover new options and error paths.
- No new security findings from gosec or govulncheck for the changed code paths.

## Testing and validation

- Unit tests for new APIs and options, including symlink policy cases.
- Fuzz tests extended to cover option combinations and path resolution.
- Benchmarks for read/write paths with and without directory fsync.

## Rollout plan

- Phase 1: Add public secure buffer package and optioned read helper.
- Phase 2: Path handling hardening and directory fsync option.
- Phase 3: Documentation and repo hygiene updates.

## Open questions

- Which platforms must be first-class for hardened path handling (linux only vs cross-platform)?
- Should `SecureReadFile` gain a default size cap, or should this be a new helper to avoid breaking change risk?
- Should the secure buffer live in `pkg/memory` or be re-exported in `pkg/io`?
