package memory

import "testing"

func BenchmarkSecureBufferClear(b *testing.B) {
	data := make([]byte, 64*1024)

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		buf := NewSecureBuffer(data)
		buf.Clear()
	}
}

func BenchmarkSecureBufferClearFast(b *testing.B) {
	data := make([]byte, 64*1024)

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		buf := NewSecureBuffer(data)
		buf.ClearFast()
	}
}
