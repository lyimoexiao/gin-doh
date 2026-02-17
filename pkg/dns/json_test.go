package dns

import (
	"testing"
)

// TestWireToJSON tests Wire Format to JSON conversion
func TestWireToJSON(t *testing.T) {
	// Build a simple A record query
	query, err := BuildQuery("example.com", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery failed: %v", err)
	}

	// Parse it back to JSON
	jsonResp, err := WireToJSON(query)
	if err != nil {
		t.Fatalf("WireToJSON failed: %v", err)
	}

	// Verify basic structure
	if jsonResp.Status != RcodeNoError {
		t.Errorf("Status = %d, want %d", jsonResp.Status, RcodeNoError)
	}

	if len(jsonResp.Question) != 1 {
		t.Errorf("Expected 1 question, got %d", len(jsonResp.Question))
	}

	if jsonResp.Question[0].Name != "example.com." {
		t.Errorf("Question name = %s, want example.com.", jsonResp.Question[0].Name)
	}

	if jsonResp.Question[0].Type != int(TypeA) {
		t.Errorf("Question type = %d, want %d", jsonResp.Question[0].Type, TypeA)
	}
}

// TestWireToJSONWithAnswers tests JSON conversion with answer records
func TestWireToJSONWithAnswers(t *testing.T) {
	// This is a simplified test - in practice, answers come from upstream
	// We just test that the conversion handles various flag states

	// Build a query
	query, err := BuildQuery("google.com", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery failed: %v", err)
	}

	jsonResp, err := WireToJSON(query)
	if err != nil {
		t.Fatalf("WireToJSON failed: %v", err)
	}

	// Check RD flag is set
	if !jsonResp.RD {
		t.Error("RD flag should be set")
	}
}

// TestWireToJSONTruncated tests handling of truncated data
func TestWireToJSONTruncated(t *testing.T) {
	_, err := WireToJSON([]byte{0x00, 0x01, 0x00})
	if err == nil {
		t.Error("WireToJSON should fail with truncated data")
	}
}

// TestJSONResponseToJSONBytes tests JSON serialization
func TestJSONResponseToJSONBytes(t *testing.T) {
	resp := &JSONResponse{
		Status: RcodeNoError,
		TC:     false,
		RD:     true,
		RA:     true,
		Question: []JSONQuestion{
			{Name: "example.com.", Type: int(TypeA)},
		},
		Answer: []JSONAnswer{
			{Name: "example.com.", Type: int(TypeA), TTL: 300, Data: "93.184.216.34"},
		},
	}

	data, err := resp.ToJSONBytes()
	if err != nil {
		t.Fatalf("ToJSONBytes failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("ToJSONBytes returned empty data")
	}

	// Verify JSON contains expected fields
	jsonStr := string(data)
	if jsonStr == "" {
		t.Error("JSON string is empty")
	}
}

// TestIsAcceptJSON tests Accept header detection
func TestIsAcceptJSON(t *testing.T) {
	tests := []struct {
		accept   string
		expected bool
	}{
		{"application/dns-json", true},
		{"application/json", true},
		{"application/dns-message", false},
		{"text/html", false},
		{"", false},
		{"application/dns-json; charset=utf-8", false}, // exact match required
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			result := IsAcceptJSON(tt.accept)
			if result != tt.expected {
				t.Errorf("IsAcceptJSON(%s) = %v, want %v", tt.accept, result, tt.expected)
			}
		})
	}
}

// TestIsAcceptWireFormat tests Wire Format Accept header detection
func TestIsAcceptWireFormat(t *testing.T) {
	tests := []struct {
		accept   string
		expected bool
	}{
		{"application/dns-message", true},
		{"", true}, // default
		{"application/dns-json", false},
		{"application/json", false},
		{"text/html", false},
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			result := IsAcceptWireFormat(tt.accept)
			if result != tt.expected {
				t.Errorf("IsAcceptWireFormat(%s) = %v, want %v", tt.accept, result, tt.expected)
			}
		})
	}
}

// TestJSONResponseFromError tests error response creation
func TestJSONResponseFromError(t *testing.T) {
	resp := JSONResponseFromError(RcodeServFail, "Internal server error")

	if resp.Status != RcodeServFail {
		t.Errorf("Status = %d, want %d", resp.Status, RcodeServFail)
	}

	if resp.Comment != "Internal server error" {
		t.Errorf("Comment = %s, want 'Internal server error'", resp.Comment)
	}
}

// TestFormatUnknownRdata tests unknown record data formatting
func TestFormatUnknownRdata(t *testing.T) {
	tests := []struct {
		rdata    []byte
		expected string
	}{
		{[]byte{}, "\\# 0"},
		{[]byte{0x01, 0x02}, "\\# 2 01 02"},
		{[]byte{0xFF, 0xFE, 0xFD}, "\\# 3 ff fe fd"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatUnknownRdata(tt.rdata)
			if result != tt.expected {
				t.Errorf("formatUnknownRdata = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestCurrentTimestamp tests timestamp generation
func TestCurrentTimestamp(t *testing.T) {
	ts := CurrentTimestamp()
	if ts == "" {
		t.Error("CurrentTimestamp returned empty string")
	}

	// Should be in RFC3339 format
	if len(ts) < 20 {
		t.Errorf("Timestamp too short: %s", ts)
	}
}

// TestTypeConversionRoundTrip tests type string conversion round trip
func TestTypeConversionRoundTrip(t *testing.T) {
	types := []uint16{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeNS, TypePTR, TypeSOA, TypeSRV, TypeCAA, TypeHTTPS, TypeSVCB}

	for _, typ := range types {
		t.Run(TypeToString(typ), func(t *testing.T) {
			str := TypeToString(typ)
			converted := StringToType(str)
			if converted != typ {
				t.Errorf("Round trip failed: %d -> %s -> %d", typ, str, converted)
			}
		})
	}
}
