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

## Cleanup

- Use `Remove`/`RemoveAll` to enforce root scoping.
- When deleting sensitive files, configure `WithRemoveWipe(true)` for best-effort overwrite before delete.

## CI and Dependency Hygiene

- Run `make sec` regularly (`govulncheck`, `gosec`, and secret scanning).
- Keep dependencies up to date and review Dependabot PRs promptly.
