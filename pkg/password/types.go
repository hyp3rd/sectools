package password

// Hasher defines a password hashing interface with upgrade detection.
type Hasher interface {
	Hash(password []byte) (string, error)
	// Verify checks whether password matches the encoded hash.
	// It returns:
	//   - bool: true if the password matches the encoded hash.
	//   - bool: true if the hash should be rehashed with updated parameters.
	Verify(password []byte, encoded string) (bool, bool, error)
}
