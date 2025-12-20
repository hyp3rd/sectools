// Package memory provides secure memory management utilities for handling sensitive data
// such as tokens, credentials, and other secrets.
package memory

import (
	"crypto/rand"
	"runtime"
	"sync"
)

// SecureBuffer represents a secure memory buffer for storing sensitive data.
// It provides automatic cleanup and protection against memory dumps.
type SecureBuffer struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecureBuffer creates a new secure buffer with the given data.
// The data is copied into the buffer to ensure isolation.
func NewSecureBuffer(data []byte) *SecureBuffer {
	buf := &SecureBuffer{
		data: make([]byte, len(data)),
	}
	copy(buf.data, data)

	// Set finalizer to ensure cleanup even if Clear() is not called
	runtime.SetFinalizer(buf, (*SecureBuffer).finalize)

	return buf
}

// Bytes returns a copy of the buffer's data.
// The returned slice is safe to use and modify.
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.data == nil {
		return nil
	}

	result := make([]byte, len(sb.data))
	copy(result, sb.data)

	return result
}

// String returns the buffer's data as a string.
// This creates a copy of the data, so the returned string is safe to use.
func (sb *SecureBuffer) String() string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.data == nil {
		return ""
	}

	return string(sb.data)
}

// Len returns the length of the buffer.
func (sb *SecureBuffer) Len() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	return len(sb.data)
}

// Clear securely wipes the buffer's memory by overwriting it with random data
// and then zeroing it out. After calling Clear(), the buffer should not be used.
func (sb *SecureBuffer) Clear() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.data == nil {
		return
	}

	// Overwrite with random data first
	_, err := rand.Read(sb.data)
	if err != nil {
		// If random read fails, at least zero it out
		for i := range sb.data {
			sb.data[i] = 0
		}
	}

	// Zero out the memory
	for i := range sb.data {
		sb.data[i] = 0
	}

	// Release the slice
	sb.data = nil

	// Clear the finalizer since we've manually cleaned up
	runtime.SetFinalizer(sb, nil)
}

// IsCleared returns true if the buffer has been cleared.
func (sb *SecureBuffer) IsCleared() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	return sb.data == nil
}

// finalize is called by the garbage collector to ensure cleanup.
func (sb *SecureBuffer) finalize() {
	sb.Clear()
}
