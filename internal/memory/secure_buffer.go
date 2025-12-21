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
	return sb.BytesCopy()
}

// BytesCopy returns a copy of the buffer's data.
// The returned slice is safe to use and modify.
func (sb *SecureBuffer) BytesCopy() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.data == nil {
		return nil
	}

	result := make([]byte, len(sb.data))
	copy(result, sb.data)

	return result
}

// Deprecated: String returns a string copy that cannot be zeroized.
// Prefer BytesCopy for sensitive data.
func (sb *SecureBuffer) String() string {
	return sb.UnsafeString()
}

// UnsafeString returns the buffer's data as a string copy.
// The resulting string cannot be zeroized and may persist in memory.
func (sb *SecureBuffer) UnsafeString() string {
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
	sb.performClear(true)
}

// ClearFast wipes the buffer's memory by zeroing it out only.
// This skips the random overwrite for speed.
func (sb *SecureBuffer) ClearFast() {
	sb.performClear(false)
}

// IsCleared returns true if the buffer has been cleared.
func (sb *SecureBuffer) IsCleared() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	return sb.data == nil
}

// ZeroBytes overwrites the buffer with zeros.
func ZeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// performClear performs the actual clearing of the buffer.
func (sb *SecureBuffer) performClear(randomize bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.data == nil {
		return
	}

	if randomize {
		// Overwrite with random data first.
		_, err := rand.Read(sb.data)
		if err != nil {
			// If random read fails, fall back to zeroing.
			ZeroBytes(sb.data)
		}
	}

	// Zero out the memory.
	ZeroBytes(sb.data)

	// Release the slice
	sb.data = nil

	// Clear the finalizer since we've manually cleaned up
	runtime.SetFinalizer(sb, nil)
}

// finalize is called by the garbage collector to ensure cleanup.
func (sb *SecureBuffer) finalize() {
	sb.Clear()
}
