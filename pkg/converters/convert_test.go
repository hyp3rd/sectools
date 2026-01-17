package converters

import (
	"math"
	"testing"
)

func TestSafeUint64FromInt(t *testing.T) {
	t.Parallel()

	value, err := SafeUint64FromInt(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 10 {
		t.Fatalf("expected 10, got %d", value)
	}

	if _, err = SafeUint64FromInt(-1); err == nil {
		t.Fatalf("expected error for negative input")
	}
}

func TestSafeUint64FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint64FromInt64(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = SafeUint64FromInt64(-5); err == nil {
		t.Fatalf("expected error for negative input")
	}
}

func TestSafeIntFromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeIntFromInt64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	maxInt := int64(^uint(0) >> 1)
	if maxInt < math.MaxInt64 {
		overflowCandidate := maxInt + 1
		if _, err = SafeIntFromInt64(overflowCandidate); err == nil {
			t.Fatalf("expected overflow error")
		}
	}
}

func TestSafeUintFromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUintFromInt64(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = SafeUintFromInt64(-1); err == nil {
		t.Fatalf("expected error for negative input")
	}

	maxUint := uint64(^uint(0))

	maxInt64 := uint64(^uint64(0) >> 1)
	if maxUint < maxInt64 {
		overflowCandidate := int64(maxUint) + 1
		if _, err = SafeUintFromInt64(overflowCandidate); err == nil {
			t.Fatalf("expected overflow error")
		}
	}
}

func TestSafeUint32FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint32FromInt64(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = SafeUint32FromInt64(-1); err == nil {
		t.Fatalf("expected error for negative input")
	}

	if _, err = SafeUint32FromInt64(int64(^uint32(0)) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeUint16FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint16FromInt64(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = SafeUint16FromInt64(-1); err == nil {
		t.Fatalf("expected error for negative input")
	}

	if _, err = SafeUint16FromInt64(int64(^uint16(0)) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeUint8FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint8FromInt64(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = SafeUint8FromInt64(-1); err == nil {
		t.Fatalf("expected error for negative input")
	}

	if _, err = SafeUint8FromInt64(int64(^uint8(0)) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeIntFromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeIntFromUint64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	maxInt := uint64(^uint(0) >> 1)
	if _, err = SafeIntFromUint64(maxInt + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeInt32FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt32FromInt64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	if _, err = SafeInt32FromInt64(int64(1 << 31)); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeInt16FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt16FromInt64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	if _, err = SafeInt16FromInt64(int64(1 << 15)); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeInt8FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt8FromInt64(12)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 12 {
		t.Fatalf("expected 12, got %d", value)
	}

	if _, err = SafeInt8FromInt64(int64(1 << 7)); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeInt64FromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt64FromUint64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	if _, err = SafeInt64FromUint64(uint64(math.MaxInt64) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestSafeUint32FromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint32FromUint64(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	if _, err = SafeUint32FromUint64(uint64(^uint32(0)) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestToInt64(t *testing.T) {
	t.Parallel()

	value, err := ToInt64(int32(123))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 123 {
		t.Fatalf("expected 123, got %d", value)
	}

	value, err = ToInt64(int8(-12))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != -12 {
		t.Fatalf("expected -12, got %d", value)
	}

	if _, err = ToInt64(uint64(math.MaxInt64) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestToInt32(t *testing.T) {
	t.Parallel()

	value, err := ToInt32(uint16(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = ToInt32(uint64(1<<31) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}

	if _, err = ToInt32(int64(-1<<31) - 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestToInt(t *testing.T) {
	t.Parallel()

	value, err := ToInt(uint16(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	maxInt := int64(^uint(0) >> 1)
	minInt := -maxInt - 1

	if _, err = ToInt(uint64(maxInt) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}

	if minInt > math.MinInt64 {
		if _, err = ToInt(minInt - 1); err == nil {
			t.Fatalf("expected overflow error")
		}
	}
}

func TestToUint64(t *testing.T) {
	t.Parallel()

	value, err := ToUint64(int32(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = ToUint64(int64(-1)); err == nil {
		t.Fatalf("expected error for negative input")
	}
}

func TestToUint32(t *testing.T) {
	t.Parallel()

	value, err := ToUint32(uint16(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = ToUint32(int64(-1)); err == nil {
		t.Fatalf("expected error for negative input")
	}

	if _, err = ToUint32(uint64(^uint32(0)) + 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestToUint(t *testing.T) {
	t.Parallel()

	value, err := ToUint(uint16(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 42 {
		t.Fatalf("expected 42, got %d", value)
	}

	if _, err = ToUint(int64(-1)); err == nil {
		t.Fatalf("expected error for negative input")
	}

	maxUint := uint64(^uint(0))
	if maxUint < math.MaxUint64 {
		if _, err = ToUint(maxUint + 1); err == nil {
			t.Fatalf("expected overflow error")
		}
	}
}
