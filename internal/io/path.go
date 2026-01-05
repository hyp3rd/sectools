package io

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/hyp3rd/ewrap"
)

const pathLabel = "path"

type resolvedPath struct {
	fullPath string
	rootPath string
	relPath  string
}

func normalizeReadOptions(opts ReadOptions) (ReadOptions, error) {
	if opts.MaxSizeBytes < 0 {
		return opts, ErrMaxSizeInvalid
	}

	if opts.DisallowPerms&^fileModeMask != 0 {
		return opts, ErrInvalidPermissions
	}

	if opts.BaseDir == "" {
		if len(opts.AllowedRoots) > 0 {
			opts.BaseDir = opts.AllowedRoots[0]
		} else {
			opts.BaseDir = os.TempDir()
		}
	}

	baseDir, err := normalizeRoot(opts.BaseDir)
	if err != nil {
		return opts, ewrap.Wrap(ErrInvalidBaseDir, "invalid base directory").
			WithMetadata(pathLabel, opts.BaseDir)
	}

	roots, err := normalizeAllowedRoots(baseDir, opts.AllowedRoots)
	if err != nil {
		return opts, err
	}

	opts.BaseDir = baseDir
	opts.AllowedRoots = roots

	return opts, nil
}

func normalizeDirOptions(opts DirOptions) (DirOptions, error) {
	if opts.DirMode == 0 {
		opts.DirMode = 0o700
	}

	if opts.DirMode&^fileModeMask != 0 {
		return opts, ErrInvalidPermissions
	}

	if opts.DisallowPerms&^fileModeMask != 0 {
		return opts, ErrInvalidPermissions
	}

	if opts.DisallowPerms != 0 && opts.DirMode&opts.DisallowPerms != 0 {
		return opts, ErrInvalidPermissions
	}

	if opts.BaseDir == "" {
		if len(opts.AllowedRoots) > 0 {
			opts.BaseDir = opts.AllowedRoots[0]
		} else {
			opts.BaseDir = os.TempDir()
		}
	}

	baseDir, err := normalizeRoot(opts.BaseDir)
	if err != nil {
		return opts, ewrap.Wrap(ErrInvalidBaseDir, "invalid base directory").
			WithMetadata(pathLabel, opts.BaseDir)
	}

	roots, err := normalizeAllowedRoots(baseDir, opts.AllowedRoots)
	if err != nil {
		return opts, err
	}

	opts.BaseDir = baseDir
	opts.AllowedRoots = roots

	return opts, nil
}

func normalizeWriteOptions(opts WriteOptions) (WriteOptions, error) {
	if opts.MaxSizeBytes < 0 {
		return opts, ErrMaxSizeInvalid
	}

	if opts.FileMode == 0 {
		opts.FileMode = 0o600
	}

	if opts.BaseDir == "" {
		if len(opts.AllowedRoots) > 0 {
			opts.BaseDir = opts.AllowedRoots[0]
		} else {
			opts.BaseDir = os.TempDir()
		}
	}

	baseDir, err := normalizeRoot(opts.BaseDir)
	if err != nil {
		return opts, ewrap.Wrap(ErrInvalidBaseDir, "invalid base directory").
			WithMetadata(pathLabel, opts.BaseDir)
	}

	roots, err := normalizeAllowedRoots(baseDir, opts.AllowedRoots)
	if err != nil {
		return opts, err
	}

	opts.BaseDir = baseDir
	opts.AllowedRoots = roots

	return opts, nil
}

func normalizeRoot(root string) (string, error) {
	if root == "" {
		return "", ErrInvalidBaseDir
	}

	absRoot := root
	if !filepath.IsAbs(absRoot) {
		var err error

		absRoot, err = filepath.Abs(absRoot)
		if err != nil {
			return "", ewrap.Wrap(err, "failed to resolve absolute path").
				WithMetadata(pathLabel, root)
		}
	}

	return filepath.Clean(absRoot), nil
}

func normalizeAllowedRoots(baseDir string, roots []string) ([]string, error) {
	if len(roots) == 0 {
		return []string{baseDir}, nil
	}

	normalized := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))

	for _, root := range roots {
		if root == "" {
			return nil, ErrInvalidAllowedRoots
		}

		absRoot, err := normalizeRoot(root)
		if err != nil {
			return nil, ewrap.Wrap(ErrInvalidAllowedRoots, "invalid allowed root").
				WithMetadata(pathLabel, root)
		}

		if _, ok := seen[absRoot]; ok {
			continue
		}

		seen[absRoot] = struct{}{}
		normalized = append(normalized, absRoot)
	}

	if !rootInList(baseDir, normalized) {
		return nil, ewrap.Wrap(ErrInvalidAllowedRoots, "base directory not in allowed roots").
			WithMetadata(pathLabel, baseDir)
	}

	return normalized, nil
}

func rootInList(baseDir string, roots []string) bool {
	for _, root := range roots {
		if samePath(root, baseDir) {
			return true
		}
	}

	return false
}

func resolvePath(input, baseDir string, allowedRoots []string, allowAbsolute bool) (resolvedPath, error) {
	if input == "" {
		return resolvedPath{}, ErrEmptyPath.WithMetadata(pathLabel, input)
	}

	if filepath.IsAbs(input) {
		if !allowAbsolute {
			return resolvedPath{}, ErrAbsolutePathNotAllowed.WithMetadata(pathLabel, input)
		}

		cleanAbs := filepath.Clean(input)

		rootPath, err := findBestRoot(cleanAbs, allowedRoots)
		if err != nil {
			return resolvedPath{}, err
		}

		relPath, err := filepath.Rel(rootPath, cleanAbs)
		if err != nil {
			return resolvedPath{}, ewrap.Wrap(err, "failed to determine relative path").
				WithMetadata(pathLabel, input)
		}

		return resolvedPath{
			fullPath: cleanAbs,
			rootPath: rootPath,
			relPath:  relPath,
		}, nil
	}

	if volume := filepath.VolumeName(input); volume != "" {
		return resolvedPath{}, ErrInvalidPath.WithMetadata(pathLabel, input)
	}

	cleanRel, err := cleanRelativePath(input)
	if err != nil {
		return resolvedPath{}, err
	}

	return resolvedPath{
		fullPath: filepath.Join(baseDir, cleanRel),
		rootPath: baseDir,
		relPath:  cleanRel,
	}, nil
}

func cleanRelativePath(input string) (string, error) {
	if input == "" {
		return "", ErrEmptyPath.WithMetadata(pathLabel, input)
	}

	if filepath.IsAbs(input) {
		return "", ErrAbsolutePathNotAllowed.WithMetadata(pathLabel, input)
	}

	if volume := filepath.VolumeName(input); volume != "" {
		return "", ErrInvalidPath.WithMetadata(pathLabel, input)
	}

	if hasTraversalSegments(input) {
		return "", ErrInvalidPath.WithMetadata(pathLabel, input)
	}

	clean := filepath.Clean(input)
	if clean == "." {
		return "", ErrInvalidPath.WithMetadata(pathLabel, input)
	}

	if !fs.ValidPath(filepath.ToSlash(clean)) {
		return "", ErrInvalidPath.WithMetadata(pathLabel, input)
	}

	return clean, nil
}

func hasTraversalSegments(path string) bool {
	return slices.Contains(splitPathSegments(path), "..")
}

func splitPathSegments(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool {
		return os.IsPathSeparator(uint8(r))
	})
}

func findBestRoot(path string, roots []string) (string, error) {
	var best string

	for _, root := range roots {
		ok, err := isWithinRoot(path, root)
		if err != nil {
			return "", err
		}

		if ok && len(root) > len(best) {
			best = root
		}
	}

	if best == "" {
		return "", ErrPathEscapesRoot.WithMetadata(pathLabel, path)
	}

	return best, nil
}

func isWithinRoot(path, root string) (bool, error) {
	if runtime.GOOS == osWindows {
		path = strings.ToLower(path)
		root = strings.ToLower(root)
	}

	path = filepath.Clean(path)
	root = filepath.Clean(root)

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false, ewrap.Wrap(err, "failed to determine relative path").
			WithMetadata(pathLabel, path)
	}

	if rel == "." {
		return true, nil
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}

	return true, nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == osWindows {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}

	return filepath.Clean(left) == filepath.Clean(right)
}
