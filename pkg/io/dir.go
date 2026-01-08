package io

import (
	"os"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// ReadDir reads a directory securely.
func (c *Client) ReadDir(path string) ([]os.DirEntry, error) {
	if c.log != nil {
		c.log.WithField("path", path).Debug("Reading directory securely")
	}

	return internalio.SecureReadDirWithOptions(path, c.read, c.log)
}

// MkdirAll creates a directory securely.
func (c *Client) MkdirAll(path string) error {
	if c.log != nil {
		c.log.WithField("path", path).Debug("Creating directory securely")
	}

	return internalio.SecureMkdirAll(path, c.dir, c.log)
}
