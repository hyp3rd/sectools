package password

import "testing"

func TestConstantTimeCompare(t *testing.T) {
	t.Parallel()

	if !ConstantTimeCompare([]byte("abc"), []byte("abc")) {
		t.Fatal("expected equal slices")
	}

	if ConstantTimeCompare([]byte("abc"), []byte("abcd")) {
		t.Fatal("expected unequal slices")
	}
}
