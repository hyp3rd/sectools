//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package io

import "os"

func validateOwnership(_ os.FileInfo, uid, gid *int, path string) error {
	if uid == nil && gid == nil {
		return nil
	}

	return ErrOwnershipUnsupported.WithMetadata(pathLabel, path)
}
