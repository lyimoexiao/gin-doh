package dns

import (
	"bytes"
	"testing"
)

// TestRcodeToString tests response code to string conversion
func TestRcodeToString(t *testing.T) {
	tests := []struct {
		rcode    int
		expected string
	}{
		{RcodeNoError, "NOERROR"},
		{RcodeFormErr, "FORMERR"},
		{RcodeServFail, "SERVFAIL"},
		{RcodeNXDomain, "NXDOMAIN"},
		{RcodeNotImp, "NOTIMP"},
		{RcodeRefused, "REFUSED"},
		{99, "UNKNOWN99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := RcodeToString(tt.rcode)
			if result != tt.expected {
				t.Errorf("RcodeToString(%d) = %s, want %s", tt.rcode, result, tt.expected)
			}
		})
	}
}

// TestTypeToString tests type to string conversion
func TestTypeToString(t *testing.T) {
	tests := []struct {
		typ      uint16
		expected string
	}{
		{TypeA, "A"},
		{TypeAAAA, "AAAA"},
		{TypeCNAME, "CNAME"},
		{TypeMX, "MX"},
		{TypeTXT, "TXT"},
		{TypeNS, "NS"},
		{TypePTR, "PTR"},
		{TypeSOA, "SOA"},
		{TypeSRV, "SRV"},
		{TypeCAA, "CAA"},
		{TypeHTTPS, "HTTPS"},
		{TypeSVCB, "SVCB"},
		{9999, "TYPE9999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TypeToString(tt.typ)
			if result != tt.expected {
				t.Errorf("TypeToString(%d) = %s, want %s", tt.typ, result, tt.expected)
			}
		})
	}
}

// TestStringToType tests string to type conversion
func TestStringToType(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
	}{
		{"A", TypeA},
		{"a", TypeA},
		{"AAAA", TypeAAAA},
		{"CNAME", TypeCNAME},
		{"MX", TypeMX},
		{"TXT", TypeTXT},
		{"NS", TypeNS},
		{"PTR", TypePTR},
		{"SOA", TypeSOA},
		{"SRV", TypeSRV},
		{"CAA", TypeCAA},
		{"HTTPS", TypeHTTPS},
		{"SVCB", TypeSVCB},
		{"TYPE65", TypeHTTPS},
		{"65", TypeHTTPS},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := StringToType(tt.input)
			if result != tt.expected {
				t.Errorf("StringToType(%s) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBuildQuery tests DNS query building
func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name    string
		qtype   uint16
		wantErr bool
	}{
		{"example.com", TypeA, false},
		{"google.com", TypeAAAA, false},
		{"cloudflare.com", TypeMX, false},
		{"example.com", TypeHTTPS, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := BuildQuery(tt.name, tt.qtype)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildQuery(%s, %d) error = %v, wantErr %v", tt.name, tt.qtype, err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(query) < HeaderSize {
					t.Errorf("BuildQuery returned query too short: %d bytes", len(query))
				}

				// Verify we can extract the query name
				extractedName, err := ExtractQueryName(query)
				if err != nil {
					t.Errorf("ExtractQueryName failed: %v", err)
				}
				if extractedName != tt.name+"." {
					t.Errorf("ExtractQueryName = %s, want %s.", extractedName, tt.name)
				}

				// Verify we can extract the query type
				extractedType, err := ExtractQueryType(query)
				if err != nil {
					t.Errorf("ExtractQueryType failed: %v", err)
				}
				if extractedType != tt.qtype {
					t.Errorf("ExtractQueryType = %d, want %d", extractedType, tt.qtype)
				}
			}
		})
	}
}

// TestBuildQueryWithOptions tests DNS query building with options
func TestBuildQueryWithOptions(t *testing.T) {
	query, err := BuildQueryWithOptions("example.com", TypeA, false, false)
	if err != nil {
		t.Fatalf("BuildQueryWithOptions failed: %v", err)
	}

	if len(query) < HeaderSize {
		t.Errorf("Query too short: %d bytes", len(query))
	}

	// Test with DO flag (DNSSEC)
	queryDO, err := BuildQueryWithOptions("example.com", TypeA, false, true)
	if err != nil {
		t.Fatalf("BuildQueryWithOptions with DO failed: %v", err)
	}

	// DO query should have EDNS0 OPT record, so it should be longer
	if len(queryDO) <= len(query) {
		t.Errorf("Query with DO flag should be longer than without")
	}

	// Test with CD flag
	queryCD, err := BuildQueryWithOptions("example.com", TypeA, true, false)
	if err != nil {
		t.Fatalf("BuildQueryWithOptions with CD failed: %v", err)
	}

	if len(queryCD) < HeaderSize {
		t.Errorf("Query with CD flag too short")
	}
}

// TestParseMessage tests DNS message parsing
func TestParseMessage(t *testing.T) {
	// Build a query and parse it
	originalQuery, err := BuildQuery("example.com", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery failed: %v", err)
	}

	msg, err := ParseMessage(originalQuery)
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}

	// Verify header
	if msg.Header.ID != 1 {
		t.Errorf("Header ID = %d, want 1", msg.Header.ID)
	}

	if msg.Header.Qdcount != 1 {
		t.Errorf("Header Qdcount = %d, want 1", msg.Header.Qdcount)
	}

	// Verify question
	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}

	if msg.Questions[0].Name != "example.com." {
		t.Errorf("Question name = %s, want example.com.", msg.Questions[0].Name)
	}

	if msg.Questions[0].Type != TypeA {
		t.Errorf("Question type = %d, want %d", msg.Questions[0].Type, TypeA)
	}
}

// TestParseMessageTooShort tests parsing of truncated messages
func TestParseMessageTooShort(t *testing.T) {
	_, err := ParseMessage([]byte{0x00, 0x01, 0x00})
	if err == nil {
		t.Error("ParseMessage should fail with truncated message")
	}
}

// TestEncodeDecodeBase64URL tests Base64 URL encoding/decoding
func TestEncodeDecodeBase64URL(t *testing.T) {
	tests := [][]byte{
		{0x00, 0x01, 0x02, 0x03},
		{0xFF, 0xFE, 0xFD},
		[]byte("hello world"),
		make([]byte, 256),
	}

	for i, data := range tests {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			encoded := EncodeBase64URL(data)
			decoded, err := DecodeBase64URL(encoded)
			if err != nil {
				t.Errorf("DecodeBase64URL failed: %v", err)
				return
			}

			if !bytes.Equal(decoded, data) {
				t.Errorf("DecodeBase64URL roundtrip failed")
			}
		})
	}
}

// TestExtractQueryName tests query name extraction
func TestExtractQueryName(t *testing.T) {
	query, err := BuildQuery("test.example.com", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery failed: %v", err)
	}

	name, err := ExtractQueryName(query)
	if err != nil {
		t.Fatalf("ExtractQueryName failed: %v", err)
	}

	if name != "test.example.com." {
		t.Errorf("ExtractQueryName = %s, want test.example.com.", name)
	}
}

// TestExtractQueryNameTooShort tests extraction from truncated data
func TestExtractQueryNameTooShort(t *testing.T) {
	_, err := ExtractQueryName([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("ExtractQueryName should fail with truncated data")
	}
}

// TestExtractQueryType tests query type extraction
func TestExtractQueryType(t *testing.T) {
	types := []uint16{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeHTTPS}

	for _, expectedType := range types {
		t.Run(TypeToString(expectedType), func(t *testing.T) {
			query, err := BuildQuery("example.com", expectedType)
			if err != nil {
				t.Fatalf("BuildQuery failed: %v", err)
			}

			extractedType, err := ExtractQueryType(query)
			if err != nil {
				t.Fatalf("ExtractQueryType failed: %v", err)
			}

			if extractedType != expectedType {
				t.Errorf("ExtractQueryType = %d, want %d", extractedType, expectedType)
			}
		})
	}
}

// TestParseName tests domain name parsing
func TestParseName(t *testing.T) {
	// Create a DNS query with known name
	query, err := BuildQuery("sub.example.com", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery failed: %v", err)
	}

	// Parse the name starting after header
	name, _, err := parseName(query, HeaderSize)
	if err != nil {
		t.Fatalf("parseName failed: %v", err)
	}

	expected := "sub.example.com."
	if name != expected {
		t.Errorf("parseName = %s, want %s", name, expected)
	}
}

// TestBuildQueryLabelTooLong tests query building with oversized label
func TestBuildQueryLabelTooLong(t *testing.T) {
	// Create a label longer than 63 characters
	longLabel := ""
	for i := 0; i < 64; i++ {
		longLabel += "a"
	}

	_, err := BuildQuery(longLabel+".com", TypeA)
	if err == nil {
		t.Error("BuildQuery should fail with label > 63 characters")
	}
}

// TestBuildQueryEmptyName tests query building with empty name
func TestBuildQueryEmptyName(t *testing.T) {
	query, err := BuildQuery("", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery with empty name failed: %v", err)
	}

	// Should create a query for the root domain
	if len(query) < HeaderSize {
		t.Error("Query too short")
	}
}
