package password

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptInteractiveCost is the low-latency bcrypt cost.
// BcryptBalancedCost is the general-purpose bcrypt cost.
// BcryptHighCost is the high-security bcrypt cost.
const (
	BcryptInteractiveCost = 10
	BcryptBalancedCost    = 12
	BcryptHighCost        = 14
)

// BcryptHasher hashes passwords using bcrypt.
type BcryptHasher struct {
	cost int
}

// NewBcrypt constructs a bcrypt hasher with the given cost.
func NewBcrypt(cost int) (*BcryptHasher, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, ErrInvalidParams
	}

	return &BcryptHasher{cost: cost}, nil
}

// Hash hashes a password using bcrypt.
func (h *BcryptHasher) Hash(password []byte) (string, error) {
	if len(password) > bcryptMaxPasswordLength {
		return "", ErrPasswordTooLong
	}

	hash, err := bcrypt.GenerateFromPassword(password, h.cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}

	return string(hash), nil
}

// Verify checks a password against a bcrypt hash and reports if it needs rehash.
func (h *BcryptHasher) Verify(password []byte, encoded string) (ok, needsRehash bool, err error) {
	if len(password) > bcryptMaxPasswordLength {
		return false, false, ErrPasswordTooLong
	}

	err = bcrypt.CompareHashAndPassword([]byte(encoded), password)
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}

		return false, false, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}

	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil {
		return true, false, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}

	needsRehash = cost != h.cost

	return true, needsRehash, nil
}

const bcryptMaxPasswordLength = 72
