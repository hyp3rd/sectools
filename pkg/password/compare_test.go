package password

import "testing"

func TestConstantTimeCompare(t *testing.T) {
	if !ConstantTimeCompare([]byte("abc"), []byte("abc")) {
		t.Fatalf("expected equal slices")
	}

	if ConstantTimeCompare([]byte("abc"), []byte("abcd")) {
		t.Fatalf("expected unequal slices")
	}
}
