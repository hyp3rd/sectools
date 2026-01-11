package sanitize

import "github.com/hyp3rd/ewrap"

var (
	// ErrInvalidHTMLConfig indicates an invalid HTML sanitizer configuration.
	ErrInvalidHTMLConfig = ewrap.New("invalid html sanitize config")
	// ErrInvalidMarkdownConfig indicates an invalid Markdown sanitizer configuration.
	ErrInvalidMarkdownConfig = ewrap.New("invalid markdown sanitize config")
	// ErrInvalidSQLConfig indicates an invalid SQL sanitizer configuration.
	ErrInvalidSQLConfig = ewrap.New("invalid sql sanitize config")
	// ErrInvalidNoSQLConfig indicates an invalid NoSQL detector configuration.
	ErrInvalidNoSQLConfig = ewrap.New("invalid nosql detector config")
	// ErrInvalidFilenameConfig indicates an invalid filename sanitizer configuration.
	ErrInvalidFilenameConfig = ewrap.New("invalid filename sanitize config")

	// ErrHTMLTooLong indicates the HTML input exceeds the configured limit.
	ErrHTMLTooLong = ewrap.New("html input too long")
	// ErrHTMLInvalid indicates the HTML input could not be parsed safely.
	ErrHTMLInvalid = ewrap.New("html input invalid")
	// ErrMarkdownTooLong indicates the Markdown input exceeds the configured limit.
	ErrMarkdownTooLong = ewrap.New("markdown input too long")

	// ErrSQLInputTooLong indicates the SQL input exceeds the configured limit.
	ErrSQLInputTooLong = ewrap.New("sql input too long")
	// ErrSQLIdentifierInvalid indicates the SQL identifier is invalid.
	ErrSQLIdentifierInvalid = ewrap.New("sql identifier invalid")
	// ErrSQLLiteralInvalid indicates the SQL literal is invalid.
	ErrSQLLiteralInvalid = ewrap.New("sql literal invalid")
	// ErrSQLLikeEscapeInvalid indicates the SQL LIKE escape character is invalid.
	ErrSQLLikeEscapeInvalid = ewrap.New("sql like escape invalid")
	// ErrSQLInjectionDetected indicates the input matched SQL injection heuristics.
	ErrSQLInjectionDetected = ewrap.New("sql injection detected")
	// ErrNoSQLInputTooLong indicates the NoSQL input exceeds the configured limit.
	ErrNoSQLInputTooLong = ewrap.New("nosql input too long")
	// ErrNoSQLInjectionDetected indicates the input matched NoSQL injection heuristics.
	ErrNoSQLInjectionDetected = ewrap.New("nosql injection detected")

	// ErrFilenameEmpty indicates the filename is empty after sanitization.
	ErrFilenameEmpty = ewrap.New("filename empty")
	// ErrFilenameTooLong indicates the filename exceeds the configured limit.
	ErrFilenameTooLong = ewrap.New("filename too long")
	// ErrFilenameInvalid indicates the filename contains invalid characters.
	ErrFilenameInvalid = ewrap.New("filename invalid")
)
