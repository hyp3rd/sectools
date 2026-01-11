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

func TestNoSQLInjectionDetectorMaxLength(t *testing.T) {
	detector, err := NewNoSQLInjectionDetector(WithNoSQLDetectMaxLength(1))
	if err != nil {
		t.Fatalf("expected detector, got %v", err)
	}

	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		// Dollar sign at end of string
		{
			name:      "dollar at end",
			input:     "price$",
			shouldErr: false,
		},
		{
			name:      "dollar at end after space",
			input:     "total amount $",
			shouldErr: false,
		},
		{
			name:      "dollar at end in JSON value",
			input:     `{"field":"value$"}`,
			shouldErr: false,
		},

		// Dollar sign followed by non-alphabetic characters
		{
			name:      "dollar followed by digit",
			input:     "$123",
			shouldErr: false,
		},
		{
			name:      "dollar followed by underscore",
			input:     "$_id",
			shouldErr: false,
		},
		{
			name:      "dollar followed by special char",
			input:     "$#value",
			shouldErr: false,
		},
		{
			name:      "dollar followed by space",
			input:     "$ amount",
			shouldErr: false,
		},

		// Dollar sign followed by valid characters but not matching any operator
		{
			name:      "unknown operator at start",
			input:     "$unknown",
			shouldErr: false,
		},
		{
			name:      "unknown operator in JSON",
			input:     `{"$unknown":"value"}`,
			shouldErr: false,
		},
		{
			name:      "unknown operator after colon",
			input:     `field:$unknown`,
			shouldErr: false,
		},
		{
			name:      "unknown operator after bracket",
			input:     `[$unknown]`,
			shouldErr: false,
		},

		// Operators in various contexts - after different delimiters
		{
			name:      "operator after open brace",
			input:     `{$ne:null}`,
			shouldErr: true,
		},
		{
			name:      "operator after open bracket",
			input:     `[$in]`,
			shouldErr: true,
		},
		{
			name:      "operator after comma",
			input:     `field1,field2,$or`,
			shouldErr: true,
		},
		{
			name:      "operator after colon",
			input:     `username:$ne`,
			shouldErr: true,
		},
		{
			name:      "operator after double quote",
			input:     `"$where"`,
			shouldErr: true,
		},
		{
			name:      "operator after single quote",
			input:     `'$exists'`,
			shouldErr: true,
		},
		{
			name:      "operator after open paren",
			input:     `($regex)`,
			shouldErr: true,
		},
		{
			name:      "operator at start of string",
			input:     `$gt`,
			shouldErr: true,
		},
		{
			name:      "operator after whitespace",
			input:     `field $lt value`,
			shouldErr: true,
		},
		{
			name:      "operator after tab",
			input:     "field\t$gte",
			shouldErr: true,
		},
		{
			name:      "operator after newline",
			input:     "field\n$lte",
			shouldErr: true,
		},

		// Mixed cases - valid operators with surrounding noise
		{
			name:      "operator-like substring mid-word",
			input:     "test$nevalue",
			shouldErr: false,
		},
		{
			name:      "dollar in middle of identifier",
			input:     "price$usd",
			shouldErr: false,
		},
		{
			name:      "multiple dollars non-operator",
			input:     "$$$",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detector.Detect(tt.input)
			if tt.shouldErr && err != ErrNoSQLInjectionDetected {
				t.Errorf("expected ErrNoSQLInjectionDetected, got %v", err)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
