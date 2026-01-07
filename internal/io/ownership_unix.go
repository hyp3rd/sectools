//go:build linux || darwin || freebsd || netbsd || openbsd

package io

import (
	"os"
	"syscall"
)

const (
	maxUint32      = ^uint32(0)
	maxUint32Int64 = int64(maxUint32)
)

func validateOwnership(info os.FileInfo, uid, gid *int, path string) error {
	if uid == nil && gid == nil {
		return nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return ErrOwnershipUnsupported.WithMetadata(pathLabel, path)
	}

	err := validateOwnershipID(uid, stat.Uid, path)
	if err != nil {
		return err
	}

	err = validateOwnershipID(gid, stat.Gid, path)
	if err != nil {
		return err
	}

	return nil
}

func validateOwnershipID(value *int, actual uint32, path string) error {
	if value == nil {
		return nil
	}

	value64 := int64(*value)
	if value64 < 0 {
		return ErrInvalidOwnership.WithMetadata(pathLabel, path)
	}

	if value64 > maxUint32Int64 {
		return ErrInvalidOwnership.WithMetadata(pathLabel, path)
	}

	if value64 != int64(actual) {
		return ErrOwnershipNotAllowed.WithMetadata(pathLabel, path)
	}

	return nil
}
