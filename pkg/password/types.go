package password

// Hasher defines a password hashing interface with upgrade detection.
type Hasher interface {
	Hash(password []byte) (string, error)
	Verify(password []byte, encoded string) (bool, bool, error)
}
