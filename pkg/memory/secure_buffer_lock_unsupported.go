//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package memory

func lockBytes(_ []byte) error {
	return ErrLockUnsupported
}

func unlockBytes(_ []byte) error {
	return ErrLockUnsupported
}
