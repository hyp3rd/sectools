// Package converters provides safe type conversion functions.
package converters

import (
	"strconv"

	"github.com/hyp3rd/ewrap"
)

// ErrNegativeValue is returned when attempting to convert a negative number to an unsigned type.
var ErrNegativeValue = ewrap.New("negative values cannot be converted to unsigned integers")

// ErrOverflow is returned when a value exceeds the target type's bounds.
var ErrOverflow = ewrap.New("value overflows target type")

// Signed represents signed integer types usable with generic converters.
type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Unsigned represents unsigned integer types usable with generic converters.
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Integer represents all integer types supported by the generic converters.
type Integer interface {
	Signed | Unsigned
}

func splitInteger[T Integer](value T) (bool, int64, uint64) {
	switch typedValue := any(value).(type) {
	case int:
		return true, int64(typedValue), 0
	case int8:
		return true, int64(typedValue), 0
	case int16:
		return true, int64(typedValue), 0
	case int32:
		return true, int64(typedValue), 0
	case int64:
		return true, typedValue, 0
	case uint:
		return false, 0, uint64(typedValue)
	case uint8:
		return false, 0, uint64(typedValue)
	case uint16:
		return false, 0, uint64(typedValue)
	case uint32:
		return false, 0, uint64(typedValue)
	case uint64:
		return false, 0, typedValue
	case uintptr:
		return false, 0, uint64(typedValue)
	}

	panic("unsupported integer type")
}

// ToInt64 converts any integer type to int64, guarding against overflow for unsigned inputs.
func ToInt64[T Integer](value T) (int64, error) {
	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		return signedValue, nil
	}

	const maxInt64U = ^uint64(0) >> 1
	if unsignedValue > maxInt64U {
		return 0, ErrOverflow
	}

	return int64(unsignedValue), nil
}

// ToInt32 converts any integer type to int32, ensuring the value fits in the target type.
func ToInt32[T Integer](value T) (int32, error) {
	const (
		maxInt32  = int64(1<<31 - 1)
		minInt32  = -1 << 31
		maxInt32U = uint64(^uint32(0) >> 1)
	)

	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		if signedValue > maxInt32 || signedValue < minInt32 {
			return 0, ErrOverflow
		}

		return int32(signedValue), nil
	}

	if unsignedValue > maxInt32U {
		return 0, ErrOverflow
	}

	return int32(unsignedValue), nil
}

// ToInt converts any integer type to int, ensuring the value fits in the target type.
func ToInt[T Integer](value T) (int, error) {
	maxInt := int64(^uint(0) >> 1)
	minInt := -maxInt - 1

	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		if signedValue > maxInt || signedValue < minInt {
			return 0, ErrOverflow
		}

		return int(signedValue), nil
	}

	maxIntU := uint64(^uint(0) >> 1)
	if unsignedValue > maxIntU {
		return 0, ErrOverflow
	}

	return int(unsignedValue), nil
}

// ToUint64 converts any integer type to uint64 while guarding against negative values.
func ToUint64[T Integer](value T) (uint64, error) {
	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		if signedValue < 0 {
			return 0, ErrNegativeValue
		}

		return uint64(signedValue), nil
	}

	return unsignedValue, nil
}

// ToUint32 converts any integer type to uint32 while guarding against negative values and overflow.
func ToUint32[T Integer](value T) (uint32, error) {
	const (
		maxUint32    = uint64(^uint32(0))
		maxUint32Int = int64(^uint32(0))
	)

	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		if signedValue < 0 {
			return 0, ErrNegativeValue
		}

		if signedValue > maxUint32Int {
			return 0, ErrOverflow
		}

		return uint32(signedValue), nil
	}

	if unsignedValue > maxUint32 {
		return 0, ErrOverflow
	}

	return uint32(unsignedValue), nil
}

// ToUint converts any integer type to uint while guarding against negative values and overflow.
func ToUint[T Integer](value T) (uint, error) {
	const intSize32 = 32

	signed, signedValue, unsignedValue := splitInteger(value)
	if signed {
		if signedValue < 0 {
			return 0, ErrNegativeValue
		}

		if strconv.IntSize == intSize32 && signedValue > int64(^uint32(0)) {
			return 0, ErrOverflow
		}

		return uint(signedValue), nil
	}

	maxUint := uint64(^uint(0))
	if unsignedValue > maxUint {
		return 0, ErrOverflow
	}

	return uint(unsignedValue), nil
}

// SafeUint64FromInt converts an int to uint64 while guarding against negative values and overflow.
func SafeUint64FromInt(value int) (uint64, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	return uint64(value), nil
}

// SafeUint64FromInt64 converts an int64 to uint64 while guarding against negative values.
func SafeUint64FromInt64(value int64) (uint64, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	return uint64(value), nil
}

// SafeIntFromInt64 converts an int64 to int, ensuring the value fits in the target type.
func SafeIntFromInt64(value int64) (int, error) {
	maxInt := int64(^uint(0) >> 1)
	minInt := -maxInt - 1

	if value > maxInt || value < minInt {
		return 0, ErrOverflow
	}

	return int(value), nil
}

// SafeUintFromInt64 converts an int64 to uint while guarding against negative values and overflow.
func SafeUintFromInt64(value int64) (uint, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	maxUint := uint64(^uint(0))
	if uint64(value) > maxUint {
		return 0, ErrOverflow
	}

	return uint(value), nil
}

// SafeUint32FromInt64 converts an int64 to uint32 while guarding against negative values and overflow.
func SafeUint32FromInt64(value int64) (uint32, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	if value > int64(^uint32(0)) {
		return 0, ErrOverflow
	}

	return uint32(value), nil
}

// SafeUint16FromInt64 converts an int64 to uint16 while guarding against negative values and overflow.
func SafeUint16FromInt64(value int64) (uint16, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	if value > int64(^uint16(0)) {
		return 0, ErrOverflow
	}

	return uint16(value), nil
}

// SafeUint8FromInt64 converts an int64 to uint8 while guarding against negative values and overflow.
func SafeUint8FromInt64(value int64) (uint8, error) {
	if value < 0 {
		return 0, ErrNegativeValue
	}

	if value > int64(^uint8(0)) {
		return 0, ErrOverflow
	}

	return uint8(value), nil
}

// SafeIntFromUint64 converts a uint64 to int, ensuring the value fits in the target type.
func SafeIntFromUint64(value uint64) (int, error) {
	maxInt := uint64(^uint(0) >> 1)
	if value > maxInt {
		return 0, ErrOverflow
	}

	return int(value), nil
}

// SafeInt32FromInt64 converts an int64 to int32, ensuring the value fits in the target type.
func SafeInt32FromInt64(value int64) (int32, error) {
	const (
		maxInt32 = int64(1<<31 - 1)
		minInt32 = -1 << 31
	)

	if value > maxInt32 || value < minInt32 {
		return 0, ErrOverflow
	}

	return int32(value), nil
}

// SafeInt16FromInt64 converts an int64 to int16, ensuring the value fits in the target type.
func SafeInt16FromInt64(value int64) (int16, error) {
	const (
		maxInt16 = int64(1<<15 - 1)
		minInt16 = -1 << 15
	)

	if value > maxInt16 || value < minInt16 {
		return 0, ErrOverflow
	}

	return int16(value), nil
}

// SafeInt8FromInt64 converts an int64 to int8, ensuring the value fits in the target type.
func SafeInt8FromInt64(value int64) (int8, error) {
	const (
		maxInt8 = int64(1<<7 - 1)
		minInt8 = -1 << 7
	)

	if value > maxInt8 || value < minInt8 {
		return 0, ErrOverflow
	}

	return int8(value), nil
}

// SafeInt64FromUint64 converts a uint64 to int64, ensuring the value fits in the target type.
func SafeInt64FromUint64(value uint64) (int64, error) {
	const maxInt64 = int64(^uint64(0) >> 1)

	if value > uint64(maxInt64) {
		return 0, ErrOverflow
	}

	return int64(value), nil
}

// SafeUint32FromUint64 converts a uint64 to uint32, ensuring the value fits in the target type.
func SafeUint32FromUint64(value uint64) (uint32, error) {
	if value > uint64(^uint32(0)) {
		return 0, ErrOverflow
	}

	return uint32(value), nil
}
