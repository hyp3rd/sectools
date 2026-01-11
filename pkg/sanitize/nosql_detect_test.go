package sanitize

import "testing"

func TestNoSQLInjectionDetectorDefault(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.Detect(`{"username":{"$ne":null}}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect(`{"$where":"sleep(1)"}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}

	err = detector.Detect("price$usd")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNoSQLInjectionDetectorCustomOperators(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector(WithNoSQLDetectOperators("custom"))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	err = detector.Detect(`{"$custom":true}`)
	if err != ErrNoSQLInjectionDetected {
		t.Fatalf("expected ErrNoSQLInjectionDetected, got %v", err)
	}
}

func TestNoSQLInjectionDetectorEdgeCases(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector()
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		// Dollar sign at end of string
		{
			name:      "dollar at end of string",
			input:     "price$",
			wantError: false,
		},
		{
			name:      "dollar at end after text",
			input:     "total_usd$",
			wantError: false,
		},
		// Dollar sign followed by non-alphabetic characters
		{
			name:      "dollar followed by digit",
			input:     "$123",
			wantError: false,
		},
		{
			name:      "dollar followed by special char",
			input:     "$@#%",
			wantError: false,
		},
		{
			name:      "dollar followed by space",
			input:     "$ ",
			wantError: false,
		},
		{
			name:      "dollar followed by underscore",
			input:     "$_test",
			wantError: false,
		},
		// Dollar sign followed by valid characters but not matching any operator
		{
			name:      "dollar with unknown operator",
			input:     "$unknown",
			wantError: false,
		},
		{
			name:      "dollar with non-operator word",
			input:     "$hello",
			wantError: false,
		},
		{
			name:      "dollar with random letters",
			input:     "$xyz",
			wantError: false,
		},
		// Operators at start of string
		{
			name:      "operator at start",
			input:     "$ne",
			wantError: true,
		},
		{
			name:      "operator at start with value",
			input:     "$where:true",
			wantError: true,
		},
		// Operators after various delimiters
		{
			name:      "operator after open brace",
			input:     "{$ne:null}",
			wantError: true,
		},
		{
			name:      "operator after open bracket",
			input:     "[$in:[1,2]]",
			wantError: true,
		},
		{
			name:      "operator after comma",
			input:     "a,$gt:5",
			wantError: true,
		},
		{
			name:      "operator after colon",
			input:     "field:$lt:10",
			wantError: true,
		},
		{
			name:      "operator after double quote",
			input:     `"$regex":"pattern"`,
			wantError: true,
		},
		{
			name:      "operator after single quote",
			input:     `'$exists':true`,
			wantError: true,
		},
		{
			name:      "operator after open paren",
			input:     "($or:[a,b])",
			wantError: true,
		},
		{
			name:      "operator after whitespace",
			input:     " $and",
			wantError: true,
		},
		{
			name:      "operator after newline",
			input:     "\n$nor",
			wantError: true,
		},
		{
			name:      "operator after tab",
			input:     "\t$not",
			wantError: true,
		},
		// Mixed cases - dollar not at boundary
		{
			name:      "dollar in middle of word",
			input:     "price$value",
			wantError: false,
		},
		{
			name:      "dollar after letter no boundary",
			input:     "a$ne",
			wantError: false,
		},
		// Multiple operators
		{
			name:      "multiple operators",
			input:     `{"$ne":1,"$gt":2}`,
			wantError: true,
		},
		// Case sensitivity checks
		{
			name:      "operator uppercase",
			input:     "$NE",
			wantError: true,
		},
		{
			name:      "operator mixed case",
			input:     "$Ne",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detector.Detect(tt.input)
			if tt.wantError {
				if err != ErrNoSQLInjectionDetected {
					t.Errorf("expected ErrNoSQLInjectionDetected for input %q, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error for input %q, got %v", tt.input, err)
				}
			}
		})
	}
}
