// Package dns provides DNS JSON response formatting utilities.
package dns

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JSONResponse is a DNS JSON response format (following Google DoH API format)
type JSONResponse struct {
	Status    int            `json:"Status"`
	TC        bool           `json:"TC"`
	RD        bool           `json:"RD"`
	RA        bool           `json:"RA"`
	AD        bool           `json:"AD"`
	CD        bool           `json:"CD"`
	Question  []JSONQuestion `json:"Question,omitempty"`
	Answer    []JSONAnswer   `json:"Answer,omitempty"`
	Authority []JSONAnswer   `json:"Authority,omitempty"`
	Comment   string         `json:"Comment,omitempty"`
}

// JSONQuestion is a JSON question format
type JSONQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

// JSONAnswer is a JSON answer format
type JSONAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// WireToJSON converts Wire Format to JSON format
func WireToJSON(data []byte) (*JSONResponse, error) {
	msg, err := ParseMessage(data)
	if err != nil {
		return nil, err
	}

	resp := &JSONResponse{
		Status: int(msg.Header.Flags & 0x0F),
		TC:     (msg.Header.Flags & 0x0200) != 0,
		RD:     (msg.Header.Flags & 0x0100) != 0,
		RA:     (msg.Header.Flags & 0x0080) != 0,
		AD:     (msg.Header.Flags & 0x0020) != 0,
		CD:     (msg.Header.Flags & 0x0010) != 0,
	}

	// Convert questions
	for _, q := range msg.Questions {
		resp.Question = append(resp.Question, JSONQuestion{
			Name: q.Name,
			Type: int(q.Type),
		})
	}

	// Convert answers
	for _, a := range msg.Answers {
		// Calculate remaining TTL (simplified, use original TTL)
		ttl := int(a.TTL)
		if ttl < 0 {
			ttl = 0
		}

		// Format data field
		dataStr := a.RdataStr

		// If parsing succeeded and non-empty, use directly
		// Otherwise use RFC 8427 format
		if dataStr == "" {
			dataStr = formatUnknownRdata(a.Rdata)
		}

		resp.Answer = append(resp.Answer, JSONAnswer{
			Name: a.Name,
			Type: int(a.Type),
			TTL:  ttl,
			Data: dataStr,
		})
	}

	return resp, nil
}

// formatUnknownRdata formats unknown type Rdata (RFC 8427 format)
func formatUnknownRdata(rdata []byte) string {
	if len(rdata) == 0 {
		return "\\# 0"
	}
	// Use space-separated hex format, consistent with Cloudflare
	return fmt.Sprintf("\\# %d %s", len(rdata), formatHexWithSpaces(rdata))
}

// formatHexWithSpaces formats hex with space separation
func formatHexWithSpaces(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " ")
}

// ToJSONBytes converts to JSON bytes
func (r *JSONResponse) ToJSONBytes() ([]byte, error) {
	return json.Marshal(r)
}

// IsAcceptJSON checks if Accept header requires JSON format
func IsAcceptJSON(accept string) bool {
	return accept == "application/dns-json" ||
		accept == "application/json"
}

// IsAcceptWireFormat checks if Accept header requires Wire Format
func IsAcceptWireFormat(accept string) bool {
	return accept == "application/dns-message" || accept == ""
}

// QueryParams DNS JSON query parameters
type QueryParams struct {
	Name string
	Type string
	CD   bool   // Disable DNSSEC
	DO   bool   // Include DNSSEC records
	ECS  string // EDNS Client Subnet
}

// JSONResponseFromError creates a JSON response from an error
func JSONResponseFromError(rcode int, comment string) *JSONResponse {
	return &JSONResponse{
		Status:  rcode,
		Comment: comment,
	}
}

// CurrentTimestamp returns the current timestamp
func CurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
