package io

// NormalizeReadOptions validates and normalizes read options.
func NormalizeReadOptions(opts ReadOptions) (ReadOptions, error) {
	return normalizeReadOptions(opts)
}

// NormalizeWriteOptions validates and normalizes write options.
func NormalizeWriteOptions(opts WriteOptions) (WriteOptions, error) {
	return normalizeWriteOptions(opts)
}

// NormalizeDirOptions validates and normalizes directory options.
func NormalizeDirOptions(opts DirOptions) (DirOptions, error) {
	return normalizeDirOptions(opts)
}

// NormalizeTempOptions validates and normalizes temp file options.
func NormalizeTempOptions(opts TempOptions) (TempOptions, error) {
	return normalizeTempOptions(opts)
}

// NormalizeRemoveOptions validates and normalizes remove options.
func NormalizeRemoveOptions(opts RemoveOptions) (RemoveOptions, error) {
	return normalizeRemoveOptions(opts)
}
