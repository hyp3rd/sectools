# Security Checklist

This checklist is a quick reference for teams using sectools in production.

## File I/O

- Set `AllowedRoots` and avoid `AllowAbsolute` unless you control the full path.
- Keep `AllowSymlinks` disabled unless you must support symlinked paths.
- Use `MaxSizeBytes` for any untrusted file input or stream.
- Use `DisallowPerms` to reject world-readable or group-writable files when appropriate.
- Use `EnforceFileMode` to avoid umask weakening newly created file permissions.
- Use `SecureWriteFromReader` for streaming data to prevent oversized writes.
- Prefer `SecureCopyFile` with `VerifyChecksum` for sensitive copies.

## Sensitive Data

- Prefer `SecureBuffer` over raw byte slices for secrets.
- Call `Clear()` as soon as sensitive data is no longer needed.
- Avoid `UnsafeString()` for secrets (strings cannot be zeroized).
- Use `Lock()`/`Unlock()` on supported platforms for best-effort memory locking.

## Cleanup

- Use `SecureRemove`/`SecureRemoveAll` to enforce root scoping.
- When deleting sensitive files, set `Wipe: true` for best-effort overwrite before delete.

## CI and Dependency Hygiene

- Run `make sec` regularly (`govulncheck`, `gosec`, and secret scanning).
- Keep dependencies up to date and review Dependabot PRs promptly.
