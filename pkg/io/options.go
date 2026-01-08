package io

import (
	"os"

	"github.com/hyp3rd/hyperlogger"
)

// Option configures a Client.
type Option func(*Client) error

// WithLogger configures the logger used by the client.
func WithLogger(log hyperlogger.Logger) Option {
	return func(c *Client) error {
		c.log = log

		return nil
	}
}

// WithBaseDir configures a base directory for all operations.
func WithBaseDir(baseDir string) Option {
	return func(c *Client) error {
		c.read.BaseDir = baseDir
		c.write.BaseDir = baseDir
		c.dir.BaseDir = baseDir
		c.temp.BaseDir = baseDir
		c.remove.BaseDir = baseDir

		return nil
	}
}

// WithAllowedRoots configures allowed roots for all operations.
func WithAllowedRoots(roots ...string) Option {
	return func(c *Client) error {
		copied := copyStrings(roots)
		c.read.AllowedRoots = copied
		c.write.AllowedRoots = copied
		c.dir.AllowedRoots = copied
		c.temp.AllowedRoots = copied
		c.remove.AllowedRoots = copied

		return nil
	}
}

// WithAllowAbsolute configures absolute path policy for all operations.
func WithAllowAbsolute(allow bool) Option {
	return func(c *Client) error {
		c.read.AllowAbsolute = allow
		c.write.AllowAbsolute = allow
		c.dir.AllowAbsolute = allow
		c.temp.AllowAbsolute = allow
		c.remove.AllowAbsolute = allow

		return nil
	}
}

// WithAllowSymlinks configures symlink policy for all operations.
func WithAllowSymlinks(allow bool) Option {
	return func(c *Client) error {
		c.read.AllowSymlinks = allow
		c.write.AllowSymlinks = allow
		c.dir.AllowSymlinks = allow
		c.temp.AllowSymlinks = allow
		c.remove.AllowSymlinks = allow

		return nil
	}
}

// WithOwnerUID configures ownership UID checks for all operations.
func WithOwnerUID(uid int) Option {
	return func(c *Client) error {
		value := uid
		c.read.OwnerUID = &value
		c.write.OwnerUID = &value
		c.dir.OwnerUID = &value
		c.temp.OwnerUID = &value
		c.remove.OwnerUID = &value

		return nil
	}
}

// WithOwnerGID configures ownership GID checks for all operations.
func WithOwnerGID(gid int) Option {
	return func(c *Client) error {
		value := gid
		c.read.OwnerGID = &value
		c.write.OwnerGID = &value
		c.dir.OwnerGID = &value
		c.temp.OwnerGID = &value
		c.remove.OwnerGID = &value

		return nil
	}
}

// WithReadMaxSize configures a max size for reads.
func WithReadMaxSize(maxBytes int64) Option {
	return func(c *Client) error {
		if maxBytes <= 0 {
			return ErrMaxSizeInvalid
		}

		c.read.MaxSizeBytes = maxBytes

		return nil
	}
}

// WithReadAllowNonRegular configures non-regular read handling.
func WithReadAllowNonRegular(allow bool) Option {
	return func(c *Client) error {
		c.read.AllowNonRegular = allow

		return nil
	}
}

// WithReadDisallowPerms configures disallowed permissions for reads.
func WithReadDisallowPerms(perms os.FileMode) Option {
	return func(c *Client) error {
		c.read.DisallowPerms = perms

		return nil
	}
}

// WithWriteMaxSize configures a max size for writes.
func WithWriteMaxSize(maxBytes int64) Option {
	return func(c *Client) error {
		if maxBytes <= 0 {
			return ErrMaxSizeInvalid
		}

		c.write.MaxSizeBytes = maxBytes

		return nil
	}
}

// WithWriteFileMode configures the file mode used for writes.
func WithWriteFileMode(mode os.FileMode) Option {
	return func(c *Client) error {
		c.write.FileMode = mode

		return nil
	}
}

// WithWriteCreateExclusive configures exclusive create behavior.
func WithWriteCreateExclusive(enable bool) Option {
	return func(c *Client) error {
		c.write.CreateExclusive = enable

		return nil
	}
}

// WithWriteDisableAtomic configures atomic write behavior.
func WithWriteDisableAtomic(disable bool) Option {
	return func(c *Client) error {
		c.write.DisableAtomic = disable

		return nil
	}
}

// WithWriteDisableSync configures fsync behavior for writes.
func WithWriteDisableSync(disable bool) Option {
	return func(c *Client) error {
		c.write.DisableSync = disable

		return nil
	}
}

// WithWriteSyncDir configures parent directory sync for writes.
func WithWriteSyncDir(enable bool) Option {
	return func(c *Client) error {
		c.write.SyncDir = enable

		return nil
	}
}

// WithWriteEnforceFileMode configures file mode enforcement for writes.
func WithWriteEnforceFileMode(enable bool) Option {
	return func(c *Client) error {
		c.write.EnforceFileMode = enable

		return nil
	}
}

// WithDirMode configures the directory mode used for MkdirAll/TempDir.
func WithDirMode(mode os.FileMode) Option {
	return func(c *Client) error {
		c.dir.DirMode = mode

		return nil
	}
}

// WithDirEnforceMode configures directory mode enforcement.
func WithDirEnforceMode(enable bool) Option {
	return func(c *Client) error {
		c.dir.EnforceMode = enable

		return nil
	}
}

// WithDirDisallowPerms configures disallowed permissions for directories.
func WithDirDisallowPerms(perms os.FileMode) Option {
	return func(c *Client) error {
		c.dir.DisallowPerms = perms

		return nil
	}
}

// WithTempFileMode configures the file mode used for temp files.
func WithTempFileMode(mode os.FileMode) Option {
	return func(c *Client) error {
		c.temp.FileMode = mode

		return nil
	}
}

// WithTempEnforceFileMode configures file mode enforcement for temp files.
func WithTempEnforceFileMode(enable bool) Option {
	return func(c *Client) error {
		c.temp.EnforceFileMode = enable

		return nil
	}
}

// WithRemoveWipe configures best-effort wiping before removal.
func WithRemoveWipe(enable bool) Option {
	return func(c *Client) error {
		c.remove.Wipe = enable

		return nil
	}
}

// WithCopyVerifyChecksum configures checksum verification for copy operations.
func WithCopyVerifyChecksum(enable bool) Option {
	return func(c *Client) error {
		c.copy.verifyChecksum = enable

		return nil
	}
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	copied := make([]string, len(values))
	copy(copied, values)

	return copied
}
