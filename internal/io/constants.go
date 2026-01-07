package io

const (
	tempFilePrefix  = ".sectools-"
	tempRandBytes   = 16
	tempMaxAttempts = 10
	fileModeMask    = 0o777
	rootDirRel      = "."
	osWindows       = "windows"
)

const (
	maxRetryAttempts = 3
	retryDelay       = 100 // milliseconds
)
