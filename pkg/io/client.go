package io

import (
	"fmt"

	"github.com/hyp3rd/hyperlogger"

	internalio "github.com/hyp3rd/sectools/internal/io"
)

// Client provides configured secure I/O helpers.
type Client struct {
	log    hyperlogger.Logger
	read   internalio.ReadOptions
	write  internalio.WriteOptions
	dir    internalio.DirOptions
	temp   internalio.TempOptions
	remove internalio.RemoveOptions
	copy   copyOptions
}

type copyOptions struct {
	verifyChecksum bool
}

// New returns a Client with default options.
func New() *Client {
	return &Client{}
}

// NewWithOptions returns a Client configured with functional options.
func NewWithOptions(opts ...Option) (*Client, error) {
	client := New()

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(client)
		if err != nil {
			return nil, err
		}
	}

	err := client.validate()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Client) validate() error {
	_, err := internalio.NormalizeReadOptions(c.read)
	if err != nil {
		return fmt.Errorf("read options: %w", err)
	}

	_, err = internalio.NormalizeWriteOptions(c.write)
	if err != nil {
		return fmt.Errorf("write options: %w", err)
	}

	_, err = internalio.NormalizeDirOptions(c.dir)
	if err != nil {
		return fmt.Errorf("dir options: %w", err)
	}

	_, err = internalio.NormalizeTempOptions(c.temp)
	if err != nil {
		return fmt.Errorf("temp options: %w", err)
	}

	_, err = internalio.NormalizeRemoveOptions(c.remove)
	if err != nil {
		return fmt.Errorf("remove options: %w", err)
	}

	return nil
}
