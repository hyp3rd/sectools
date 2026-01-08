package io

import internalio "github.com/hyp3rd/sectools/internal/io"

// Remove removes a file or empty directory securely.
func (c *Client) Remove(path string) error {
	if c.log != nil {
		c.log.WithField("path", path).Debug("Removing path securely")
	}

	return internalio.SecureRemove(path, c.remove, c.log)
}

// RemoveAll removes a directory tree securely.
func (c *Client) RemoveAll(path string) error {
	if c.log != nil {
		c.log.WithField("path", path).Debug("Removing path tree securely")
	}

	return internalio.SecureRemoveAll(path, c.remove, c.log)
}
