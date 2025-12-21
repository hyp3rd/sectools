package io

import (
	"os"
	"path/filepath"

	"github.com/hyp3rd/ewrap"
)

func enforceSymlinkPolicy(fullPath, rootPath, relPath string, allowSymlinks, allowMissingFinal bool) error {
	if allowSymlinks {
		return ensureResolvedWithinRoot(fullPath, rootPath, allowMissingFinal)
	}

	return rejectSymlinkComponents(rootPath, relPath, allowMissingFinal)
}

func rejectSymlinkComponents(rootPath, relPath string, allowMissingFinal bool) error {
	parts, err := relPathSegments(relPath)
	if err != nil {
		return err
	}

	current := rootPath
	for _, part := range parts {
		current = filepath.Join(current, part)

		info, err := os.Lstat(current)
		if err != nil {
			return handleLstatError(err, allowMissingFinal, current)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return ErrSymlinkNotAllowed.WithMetadata(pathLabel, current)
		}
	}

	return nil
}

func relPathSegments(relPath string) ([]string, error) {
	if relPath == "" || relPath == "." {
		return nil, ErrInvalidPath.WithMetadata(pathLabel, relPath)
	}

	parts := splitPathSegments(relPath)
	if len(parts) == 0 {
		return nil, ErrInvalidPath.WithMetadata(pathLabel, relPath)
	}

	return parts, nil
}

func handleLstatError(err error, allowMissingFinal bool, current string) error {
	if os.IsNotExist(err) {
		if allowMissingFinal {
			return nil
		}

		return ewrap.Wrap(err, "path does not exist").
			WithMetadata(pathLabel, current)
	}

	return ewrap.Wrap(err, "failed to stat path").
		WithMetadata(pathLabel, current)
}

// ensureResolvedWithinRoot ensures that the resolved fullPath is within the rootPath.
//
//nolint:revive
func ensureResolvedWithinRoot(fullPath, rootPath string, allowMissingFinal bool) error {
	resolvedRoot := rootPath

	rootResolved, err := filepath.EvalSymlinks(rootPath)
	if err == nil {
		resolvedRoot = rootResolved
	}

	resolved, err := filepath.EvalSymlinks(fullPath)
	if err == nil {
		ok, err := isWithinRoot(resolved, resolvedRoot)
		if err != nil {
			return err
		}

		if !ok {
			return ErrPathEscapesRoot.WithMetadata(pathLabel, fullPath)
		}

		return nil
	}

	if allowMissingFinal && os.IsNotExist(err) {
		parent := filepath.Dir(fullPath)

		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return ewrap.Wrap(err, "failed to resolve parent").
				WithMetadata(pathLabel, parent)
		}

		ok, err := isWithinRoot(resolvedParent, resolvedRoot)
		if err != nil {
			return err
		}

		if !ok {
			return ErrPathEscapesRoot.WithMetadata(pathLabel, fullPath)
		}

		return nil
	}

	return ewrap.Wrap(err, "failed to resolve symlink").
		WithMetadata(pathLabel, fullPath)
}
