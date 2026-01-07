//go:build linux || darwin || freebsd || netbsd || openbsd

package memory

import (
	"syscall"

	"github.com/hyp3rd/ewrap"
)

func lockBytes(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	err := syscall.Mlock(buf)
	if err != nil {
		return ewrap.Wrap(err, "failed to lock memory")
	}

	return nil
}

func unlockBytes(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	err := syscall.Munlock(buf)
	if err != nil {
		return ewrap.Wrap(err, "failed to unlock memory")
	}

	return nil
}
