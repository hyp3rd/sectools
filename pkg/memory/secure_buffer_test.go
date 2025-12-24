package memory

import (
	"bytes"
	"runtime"
	"testing"
)

func TestNewSecureBuffer(t *testing.T) {
	// Test with non-empty data
	originalData := []byte("sensitive data")
	buf := NewSecureBuffer(originalData)

	// Verify data was copied correctly
	if !bytes.Equal(buf.data, originalData) {
		t.Errorf("Expected buffer data to equal original data")
	}

	// Verify the buffer is using a different memory location
	originalData[0] = 'X'

	if buf.data[0] == 'X' {
		t.Errorf("Buffer should contain a copy of the data, not a reference")
	}

	// Test with empty data
	emptyBuf := NewSecureBuffer([]byte{})
	if len(emptyBuf.data) != 0 {
		t.Errorf("Expected empty buffer for empty input")
	}
}

func TestClear(t *testing.T) {
	// Create a buffer with test data
	testData := []byte("test data")
	buf := NewSecureBuffer(testData)

	// Clear the buffer
	buf.Clear()

	// Verify data was cleared
	if buf.data != nil {
		t.Errorf("Buffer data should be nil after clearing")
	}

	// Test clearing an already cleared buffer
	buf.Clear() // Should not panic
}

func TestClearFast(t *testing.T) {
	buf := NewSecureBuffer([]byte("fast clear"))

	buf.ClearFast()

	if buf.data != nil {
		t.Errorf("Buffer data should be nil after fast clearing")
	}

	buf.ClearFast() // Should not panic
}

func TestBytes(t *testing.T) {
	// Create a buffer with test data
	testData := []byte("test data")
	buf := NewSecureBuffer(testData)

	// Get bytes from buffer
	retrievedData := buf.BytesCopy()

	// Verify data matches
	if !bytes.Equal(retrievedData, testData) {
		t.Errorf("Retrieved data doesn't match original data")
	}

	retrievedAlias := buf.Bytes()
	if !bytes.Equal(retrievedAlias, testData) {
		t.Errorf("Bytes alias mismatch")
	}
}

func TestString(t *testing.T) {
	// Create a buffer with test data
	testData := []byte("test data")
	buf := NewSecureBuffer(testData)

	// Get string from buffer
	str := buf.String()
	unsafeStr := buf.UnsafeString()

	// Verify string matches
	if str != string(testData) {
		t.Errorf("String representation doesn't match original data")
	}

	if unsafeStr != string(testData) {
		t.Errorf("Unsafe string representation doesn't match original data")
	}
}

func TestFinalizer(t *testing.T) {
	// This is a best-effort test for the finalizer behavior
	// It's not deterministic due to garbage collection unpredictability

	// Create a buffer that will go out of scope
	func() {
		buf := NewSecureBuffer([]byte("secret data"))
		_ = buf // avoid unused variable warning
	}()

	// Force garbage collection
	runtime.GC()

	// We can't actually verify the Clear() was called by the finalizer
	// since we don't have access to the buffer anymore, but this at least
	// ensures the code path doesn't panic
}

func TestSecureBufferNilInput(t *testing.T) {
	buf := NewSecureBuffer(nil)
	if len(buf.data) != 0 {
		t.Errorf("Expected 0 len data for nil input")
	}
}

func TestSecureBufferLargeData(t *testing.T) {
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	buf := NewSecureBuffer(largeData)
	if len(buf.data) != len(largeData) {
		t.Errorf("Buffer size mismatch for large data")
	}

	for i := range largeData {
		if buf.data[i] != largeData[i] {
			t.Errorf("Data mismatch at index %d", i)

			break
		}
	}
}

func TestSecureBufferMultipleCopies(t *testing.T) {
	original := []byte("sensitive data")
	buf1 := NewSecureBuffer(original)
	buf2 := NewSecureBuffer(buf1.BytesCopy())

	if !bytes.Equal(buf1.data, buf2.data) {
		t.Errorf("Data mismatch between buffer copies")
	}

	buf1.Clear()

	if buf2.data == nil {
		t.Errorf("Clearing one buffer should not affect others")
	}
}

func TestSecureBufferConcurrentAccess(t *testing.T) {
	data := []byte("concurrent test data")
	buf := NewSecureBuffer(data)

	done := make(chan bool)

	go func() {
		for range 1000 {
			_ = buf.BytesCopy()
			_ = buf.UnsafeString()
		}

		done <- true
	}()

	go func() {
		for range 1000 {
			runtime.GC()
		}

		done <- true
	}()

	<-done
	<-done
}

func TestSecureBufferZeroLengthData(t *testing.T) {
	buf := NewSecureBuffer(make([]byte, 0))
	if buf.data == nil {
		t.Errorf("Zero length buffer should not be nil")
	}

	if len(buf.data) != 0 {
		t.Errorf("Zero length buffer should have length 0")
	}
}

func TestSecureBufferStringWithNonUTF8(t *testing.T) {
	invalidUTF8 := []byte{0xFF, 0xFE, 0xFD}
	buf := NewSecureBuffer(invalidUTF8)

	str := buf.UnsafeString()
	if len(str) != len(invalidUTF8) {
		t.Errorf("String length mismatch for non-UTF8 data")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	ZeroBytes(data)

	if !bytes.Equal(data, []byte{0, 0, 0, 0}) {
		t.Errorf("Expected zeroed bytes")
	}

	ZeroBytes(nil) // Should not panic
}
