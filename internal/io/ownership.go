package io

import (
	"os"

	"github.com/hyp3rd/ewrap"
)

func validateOwnershipOptions(uid, gid *int) error {
	if uid != nil && *uid < 0 {
		return ErrInvalidOwnership
	}

	if gid != nil && *gid < 0 {
		return ErrInvalidOwnership
	}

	return nil
}

func validateFileOwnership(file *os.File, uid, gid *int, path string) error {
	if uid == nil && gid == nil {
		return nil
	}

	info, err := file.Stat()
	if err != nil {
		return ewrap.Wrap(err, "failed to stat file").WithMetadata(pathLabel, path)
	}

	return validateOwnership(info, uid, gid, path)
}
