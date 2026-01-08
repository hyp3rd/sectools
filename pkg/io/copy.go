package io

import internalio "github.com/hyp3rd/sectools/internal/io"

// CopyFile copies a file securely.
func (c *Client) CopyFile(src, dest string) error {
	if c.log != nil {
		c.log.WithField("src", src).WithField("dest", dest).Debug("Copying file securely")
	}

	return internalio.SecureCopyFile(
		src,
		dest,
		c.read,
		c.write,
		c.copy.verifyChecksum,
		c.log,
	)
}
