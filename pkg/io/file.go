// Package io provides secure file read and write helpers, including
// path validation and secure-buffer convenience functions.
package io

import (
	"io"
	"os"

	internalio "github.com/hyp3rd/sectools/internal/io"
	"github.com/hyp3rd/sectools/pkg/memory"
)

// ReadFile reads a file securely and returns the contents as a byte slice.
func (c *Client) ReadFile(file string) ([]byte, error) {
	if c.log != nil {
		c.log.WithField("file", file).Debug("Reading file securely")
	}

	return internalio.SecureReadFileWithOptions(file, c.read, c.log)
}

// OpenFile opens a file for streaming reads.
func (c *Client) OpenFile(file string) (*os.File, error) {
	if c.log != nil {
		c.log.WithField("file", file).Debug("Opening file securely")
	}

	return internalio.SecureOpenFile(file, c.read, c.log)
}

// ReadFileWithSecureBuffer reads a file securely and returns the contents
// in a SecureBuffer for better memory protection.
func (c *Client) ReadFileWithSecureBuffer(filename string) (*memory.SecureBuffer, error) {
	if c.log != nil {
		c.log.WithField("file", filename).Debug("Reading file securely into secure buffer")
	}

	return internalio.SecureReadFileWithSecureBufferOptions(filename, c.read, c.log)
}

// WriteFile writes data to a file securely.
func (c *Client) WriteFile(file string, data []byte) error {
	if c.log != nil {
		c.log.WithField("file", file).Debug("Writing file securely")
	}

	return internalio.SecureWriteFile(file, data, c.write, c.log)
}

// WriteFromReader writes data from a reader to a file securely.
func (c *Client) WriteFromReader(file string, reader io.Reader) error {
	if c.log != nil {
		c.log.WithField("file", file).Debug("Writing file securely from reader")
	}

	return internalio.SecureWriteFromReader(file, reader, c.write, c.log)
}
