package io

import (
	"os"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// TempFile creates a temp file securely.
func (c *Client) TempFile(prefix string) (*os.File, error) {
	if c.log != nil {
		c.log.WithField("prefix", prefix).Debug("Creating temp file securely")
	}

	return internalio.SecureTempFile(prefix, c.temp, c.log)
}

// TempDir creates a temp directory securely.
func (c *Client) TempDir(prefix string) (string, error) {
	if c.log != nil {
		c.log.WithField("prefix", prefix).Debug("Creating temp directory securely")
	}

	return internalio.SecureTempDir(prefix, c.dir, c.log)
}
