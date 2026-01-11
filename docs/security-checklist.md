# Security Checklist

This checklist is a quick reference for teams using sectools in production.

## File I/O

- Set `WithAllowedRoots` and avoid `WithAllowAbsolute(true)` unless you control the full path.
- Keep `WithAllowSymlinks(true)` disabled unless you must support symlinked paths.
- Use `WithReadMaxSize`/`WithWriteMaxSize` for any untrusted file input or stream.
- Use `WithReadDisallowPerms`/`WithDirDisallowPerms` to reject world-readable or group-writable files when appropriate.
- Use `WithWriteEnforceFileMode` to avoid umask weakening newly created file permissions.
- Use `WriteFromReader` for streaming data to prevent oversized writes.
- Prefer `CopyFile` with `WithCopyVerifyChecksum(true)` for sensitive copies.

## Sensitive Data

- Prefer `SecureBuffer` over raw byte slices for secrets.
- Call `Clear()` as soon as sensitive data is no longer needed.
- Avoid `UnsafeString()` for secrets (strings cannot be zeroized).
- Use `Lock()`/`Unlock()` on supported platforms for best-effort memory locking.

## Auth Tokens

- Require `iss`/`aud` checks for JWT verification and keep `WithJWTAllowedAlgorithms` tight.
- Use `WithJWTVerificationKeys` with `kid` for key rotation and enforce short expirations.
- Prefer PASETO v4 local/public helpers for new tokens and keep issuer/audience rules consistent.

## Passwords

- Use Argon2id presets unless you need bcrypt compatibility.
- Rehash stored passwords when `needsRehash` is true.
- Enforce bcrypt's 72-byte limit to avoid silent truncation.

## Input Validation

- Use `pkg/validate` for email/URL parsing instead of ad-hoc regexes.
- Enable DNS verification only when you can tolerate network lookups and timeouts.
- Keep URL schemes restricted and avoid enabling private IPs unless required.

## Sanitization

- Use `pkg/sanitize` for HTML/Markdown sanitization instead of ad-hoc escaping.
- Prefer parameterized SQL queries; use `SQLSanitizer` only for identifiers or literals when needed.
- Use `SQLInjectionDetector` as a heuristic guard for untrusted input before query composition.
- Use `NoSQLInjectionDetector` to flag operator injection in untrusted JSON-like input.

## Cleanup

- Use `Remove`/`RemoveAll` to enforce root scoping.
- When deleting sensitive files, configure `WithRemoveWipe(true)` for best-effort overwrite before delete.

## CI and Dependency Hygiene

- Run `make sec` regularly (`govulncheck`, `gosec`, and secret scanning).
- Keep dependencies up to date and review Dependabot PRs promptly.
