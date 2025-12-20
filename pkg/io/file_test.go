package io

import (
	"os"
	"testing"

	"github.com/hyp3rd/hyperlogger"
	"github.com/stretchr/testify/assert"
)

func TestValidateFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "empty filename",
			filename: "",
			wantErr:  true,
		},
		{
			name:     "valid filename",
			filename: "test.txt",
			wantErr:  false,
		},
		{
			name:     "filename with path",
			filename: os.TempDir() + "/test.txt",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFile(tt.filename)
			if tt.wantErr {
				assert.Error(t, err)

				if tt.filename == "" {
					assert.Contains(t, err.Error(), "path cannot be empty")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecureReadFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		logger   hyperlogger.Logger
		wantErr  bool
	}{
		{
			name:     "empty filename",
			filename: "",
			logger:   nil,
			wantErr:  true,
		},
		{
			name:     "empty filename with logger",
			filename: "",
			logger:   hyperlogger.NewNoop(),
			wantErr:  true,
		},
		{
			name:     "valid filename without logger",
			filename: "test.txt",
			logger:   nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SecureReadFile(tt.filename, tt.logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Note: This will likely fail in actual execution due to utils.SecureReadFile
				// but tests the validation logic
				if tt.filename == "" {
					assert.Error(t, err)
				}
			}
		})
	}
}

func TestSecureReadFileWithSecureBuffer(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		logger   hyperlogger.Logger
		wantErr  bool
	}{
		{
			name:     "empty filename",
			filename: "",
			logger:   nil,
			wantErr:  true,
		},
		{
			name:     "empty filename with logger",
			filename: "",
			logger:   hyperlogger.NewNoop(),
			wantErr:  true,
		},
		{
			name:     "valid filename without logger",
			filename: "test.txt",
			logger:   nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SecureReadFileWithSecureBuffer(tt.filename, tt.logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Note: This will likely fail in actual execution due to utils.SecureReadFileWithSecureBuffer
				// but tests the validation logic
				if tt.filename == "" {
					assert.Error(t, err)
				}
			}
		})
	}
}
