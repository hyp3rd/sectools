package converters

import (
	"math"
	"testing"
)

const (
	errMsgNegativeInput   = "expected error for negative input"
	errMsgOverflow        = "expected overflow error"
	errMsgUnexpected      = "unexpected error: %v"
	errMsgUnexpectedValue = "expected %v, got %d"
)

const (
	testValue      = 42
	testValueInt64 = 123
	int8Value      = 12
)

func TestSafeUint64FromInt(t *testing.T) {
	t.Parallel()

	value, err := SafeUint64FromInt(10)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != 10 {
		t.Fatalf("expected 10, got %d", value)
	}

	_, err = SafeUint64FromInt(-1)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}
}

func TestSafeUint64FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint64FromInt64(testValue)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = SafeUint64FromInt64(-5)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}
}

func TestSafeIntFromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeIntFromInt64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	maxInt := int64(^uint(0) >> 1)
	if maxInt < math.MaxInt64 {
		overflowCandidate := maxInt + 1

		_, err = SafeIntFromInt64(overflowCandidate)
		if err == nil {
			t.Fatal(errMsgOverflow)
		}
	}
}

func TestSafeUintFromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUintFromInt64(testValue)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = SafeUintFromInt64(-1)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	maxUint := uint64(^uint(0))

	maxInt64 := uint64(^uint64(0) >> 1)
	if maxUint < maxInt64 {
		overflowCandidate := int64(maxUint) + 1

		_, err = SafeUintFromInt64(overflowCandidate)
		if err == nil {
			t.Fatal(errMsgOverflow)
		}
	}
}

func TestSafeUint32FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint32FromInt64(testValue)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = SafeUint32FromInt64(-1)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	_, err = SafeUint32FromInt64(int64(^uint32(0)) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeUint16FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint16FromInt64(testValue)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = SafeUint16FromInt64(-1)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	_, err = SafeUint16FromInt64(int64(^uint16(0)) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeUint8FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint8FromInt64(testValue)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = SafeUint8FromInt64(-1)
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	_, err = SafeUint8FromInt64(int64(^uint8(0)) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeIntFromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeIntFromUint64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	maxInt := uint64(^uint(0) >> 1)

	_, err = SafeIntFromUint64(maxInt + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeInt32FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt32FromInt64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	_, err = SafeInt32FromInt64(int64(1 << 31))
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeInt16FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt16FromInt64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	_, err = SafeInt16FromInt64(int64(1 << 15))
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeInt8FromInt64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt8FromInt64(int8Value)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != int8Value {
		t.Fatalf("expected %d, got %d", int8Value, value)
	}

	_, err = SafeInt8FromInt64(int64(1 << 7))
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeInt64FromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeInt64FromUint64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	_, err = SafeInt64FromUint64(uint64(math.MaxInt64) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestSafeUint32FromUint64(t *testing.T) {
	t.Parallel()

	value, err := SafeUint32FromUint64(testValueInt64)
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	_, err = SafeUint32FromUint64(uint64(^uint32(0)) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestToInt64(t *testing.T) {
	t.Parallel()

	value, err := ToInt64(int32(testValueInt64))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValueInt64 {
		t.Fatalf(errMsgUnexpectedValue, testValueInt64, value)
	}

	value, err = ToInt64(int8(-int8Value))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != -int8Value {
		t.Fatalf(errMsgUnexpectedValue, -int8Value, value)
	}

	_, err = ToInt64(uint64(math.MaxInt64) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestToInt32(t *testing.T) {
	t.Parallel()

	value, err := ToInt32(uint16(testValue))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = ToInt32(uint64(1<<31) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}

	_, err = ToInt32(int64(-1<<31) - 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestToInt(t *testing.T) {
	t.Parallel()

	value, err := ToInt(uint16(testValue))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	maxInt := int64(^uint(0) >> 1)
	minInt := -maxInt - 1
	//nolint:gosec
	_, err = ToInt(uint64(maxInt) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}

	if minInt > math.MinInt64 {
		_, err = ToInt(minInt - 1)
		if err == nil {
			t.Fatal(errMsgOverflow)
		}
	}
}

func TestToUint64(t *testing.T) {
	t.Parallel()

	value, err := ToUint64(int32(testValue))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = ToUint64(int64(-1))
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}
}

func TestToUint32(t *testing.T) {
	t.Parallel()

	value, err := ToUint32(uint16(testValue))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = ToUint32(int64(-1))
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	_, err = ToUint32(uint64(^uint32(0)) + 1)
	if err == nil {
		t.Fatal(errMsgOverflow)
	}
}

func TestToUint(t *testing.T) {
	t.Parallel()

	value, err := ToUint(uint16(testValue))
	if err != nil {
		t.Fatalf(errMsgUnexpected, err)
	}

	if value != testValue {
		t.Fatalf(errMsgUnexpectedValue, testValue, value)
	}

	_, err = ToUint(int64(-1))
	if err == nil {
		t.Fatal(errMsgNegativeInput)
	}

	maxUint := uint64(^uint(0))
	if maxUint < math.MaxUint64 {
		_, err = ToUint(maxUint + 1)
		if err == nil {
			t.Fatal(errMsgOverflow)
		}
	}
}
