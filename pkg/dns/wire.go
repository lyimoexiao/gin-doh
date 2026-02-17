// Package dns provides DNS message parsing and encoding utilities.
package dns

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DNS message constants
const (
	HeaderSize = 12

	// DNS record types
	TypeA     = 1
	TypeAAAA  = 28
	TypeCNAME = 5
	TypeMX    = 15
	TypeTXT   = 16
	TypeNS    = 2
	TypePTR   = 12
	TypeSOA   = 6
	TypeSRV   = 33
	TypeCAA   = 257
	TypeHTTPS = 65 // HTTPS SVCB record (RFC 9460)
	TypeSVCB  = 64 // SVCB record (RFC 9460)

	// DNS response codes
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

// Header is a DNS message header
type Header struct {
	ID      uint16
	Flags   uint16
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

// Question is a DNS question
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord is a DNS resource record
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	Rdata    []byte
	RdataStr string // For JSON output
}

// Message is a DNS message
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
	rawData    []byte // Store raw data for parsing compressed pointers
}

// RcodeToString converts response code to string
func RcodeToString(rcode int) string {
	switch rcode {
	case RcodeNoError:
		return "NOERROR"
	case RcodeFormErr:
		return "FORMERR"
	case RcodeServFail:
		return "SERVFAIL"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNotImp:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("UNKNOWN%d", rcode)
	}
}

// TypeToString converts type to string
func TypeToString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeNS:
		return "NS"
	case TypePTR:
		return "PTR"
	case TypeSOA:
		return "SOA"
	case TypeSRV:
		return "SRV"
	case TypeCAA:
		return "CAA"
	case TypeHTTPS:
		return "HTTPS"
	case TypeSVCB:
		return "SVCB"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// StringToType converts string to type
func StringToType(s string) uint16 {
	upper := strings.ToUpper(s)

	// Check well-known types
	if t, ok := stringToTypeMap[upper]; ok {
		return t
	}

	// Try parsing TYPExxx format
	if len(upper) > 4 && upper[:4] == "TYPE" {
		num, _ := strconv.Atoi(s[4:])
		return uint16(num)
	}

	// Try parsing pure number format (e.g., "65")
	num, err := strconv.Atoi(s)
	if err == nil && num > 0 {
		return uint16(num)
	}

	return 0
}

// stringToTypeMap maps DNS type strings to their numeric values
var stringToTypeMap = map[string]uint16{
	"A":     TypeA,
	"AAAA":  TypeAAAA,
	"CNAME": TypeCNAME,
	"MX":    TypeMX,
	"TXT":   TypeTXT,
	"NS":    TypeNS,
	"PTR":   TypePTR,
	"SOA":   TypeSOA,
	"SRV":   TypeSRV,
	"CAA":   TypeCAA,
	"HTTPS": TypeHTTPS,
	"SVCB":  TypeSVCB,
}

// ParseMessage parses a DNS message
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("message too short")
	}

	msg := &Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			Flags:   binary.BigEndian.Uint16(data[2:4]),
			Qdcount: binary.BigEndian.Uint16(data[4:6]),
			Ancount: binary.BigEndian.Uint16(data[6:8]),
			Nscount: binary.BigEndian.Uint16(data[8:10]),
			Arcount: binary.BigEndian.Uint16(data[10:12]),
		},
		rawData: data,
	}

	offset := HeaderSize

	// Parse questions
	for i := uint16(0); i < msg.Header.Qdcount; i++ {
		q, newOffset, err := parseQuestion(data, offset)
		if err != nil {
			return nil, err
		}
		msg.Questions = append(msg.Questions, q)
		offset = newOffset
	}

	// Parse answers
	for i := uint16(0); i < msg.Header.Ancount; i++ {
		rr, newOffset, err := parseResourceRecordWithContext(data, offset, msg.rawData)
		if err != nil {
			return nil, err
		}
		msg.Answers = append(msg.Answers, *rr)
		offset = newOffset
	}

	return msg, nil
}

// parseQuestion parses a DNS question
func parseQuestion(data []byte, offset int) (q Question, newOffset int, err error) {
	name, newOffset, err := parseName(data, offset)
	if err != nil {
		return Question{}, 0, err
	}

	if newOffset+4 > len(data) {
		return Question{}, 0, errors.New("invalid question format")
	}

	return Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
	}, newOffset + 4, nil
}

// parseResourceRecordWithContext parses a resource record (with full message context)
func parseResourceRecordWithContext(data []byte, offset int, fullMsg []byte) (rr *ResourceRecord, newOffset int, err error) {
	name, newOffset, err := parseName(data, offset)
	if err != nil {
		return nil, 0, err
	}

	if newOffset+10 > len(data) {
		return nil, 0, errors.New("invalid resource record format")
	}

	rr = &ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
		TTL:   binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
	}

	rdlength := binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10])
	rdataStart := newOffset + 10
	rr.Rdata = make([]byte, rdlength)
	copy(rr.Rdata, data[rdataStart:rdataStart+int(rdlength)])

	// Use full message data to format Rdata, supporting compression pointers
	rr.RdataStr = formatRdataWithContext(rr.Type, rr.Rdata, fullMsg, rdataStart)

	return rr, rdataStart + int(rdlength), nil
}

// parseName parses a domain name (with compression support)
func parseName(data []byte, offset int) (name string, newOffset int, err error) {
	var labels []string
	visited := make(map[int]bool)
	jumped := false
	returnOffset := offset

	for {
		if offset >= len(data) {
			return "", 0, errors.New("invalid name")
		}

		b := data[offset]

		// Check for pointer
		if b&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, errors.New("invalid pointer")
			}

			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)

			if visited[pointer] {
				return "", 0, errors.New("circular pointer")
			}
			visited[pointer] = true

			// If this is the first jump, record return position
			if !jumped {
				returnOffset = offset + 2
				jumped = true
			}

			offset = pointer
			continue
		}

		if b == 0 {
			if len(labels) == 0 {
				return ".", offset + 1, nil
			}
			offset++ // Skip terminator
			break
		}

		labelLen := int(b)
		if offset+1+labelLen > len(data) {
			return "", 0, errors.New("invalid label")
		}

		labels = append(labels, string(data[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}

	// If jumped, return pre-jump position; otherwise return current position
	if jumped {
		return strings.Join(labels, ".") + ".", returnOffset, nil
	}
	return strings.Join(labels, ".") + ".", offset, nil
}

// formatRdataWithContext formats Rdata to string (full version)
func formatRdataWithContext(rrtype uint16, rdata, fullMsg []byte, rdataOffset int) string {
	switch rrtype {
	case TypeA:
		return formatA(rdata)
	case TypeAAAA:
		return formatAAAA(rdata)
	case TypeCNAME, TypeNS, TypePTR:
		return formatNameRecord(rdata, fullMsg, rdataOffset)
	case TypeMX:
		return formatMX(rdata, fullMsg, rdataOffset)
	case TypeTXT:
		return formatTXT(rdata)
	case TypeHTTPS, TypeSVCB:
		return formatSVCB(rdata, fullMsg, rdataOffset)
	default:
		return fmt.Sprintf("%x", rdata)
	}
}

// formatA formats A record
func formatA(rdata []byte) string {
	if len(rdata) == 4 {
		return net.IP(rdata).String()
	}
	return fmt.Sprintf("%x", rdata)
}

// formatAAAA formats AAAA record
func formatAAAA(rdata []byte) string {
	if len(rdata) == 16 {
		return net.IP(rdata).String()
	}
	return fmt.Sprintf("%x", rdata)
}

// formatNameRecord formats CNAME/NS/PTR records
func formatNameRecord(rdata, fullMsg []byte, rdataOffset int) string {
	if len(rdata) == 0 {
		return ""
	}
	// If we have full message, try parsing with compression pointer
	if len(fullMsg) > 0 {
		name, _, err := parseName(fullMsg, rdataOffset)
		if err == nil && name != "." {
			return name
		}
	}
	// Fall back to simple parsing
	name, _, err := parseNameSimple(rdata, 0)
	if err == nil && name != "." {
		return name
	}
	return ""
}

// formatMX formats MX record
func formatMX(rdata, fullMsg []byte, rdataOffset int) string {
	if len(rdata) < 3 {
		return ""
	}
	priority := binary.BigEndian.Uint16(rdata[0:2])
	if len(fullMsg) > 0 {
		name, _, err := parseName(fullMsg, rdataOffset+2)
		if err == nil && name != "." {
			return fmt.Sprintf("%d %s", priority, name)
		}
	}
	name, _, _ := parseNameSimple(rdata, 2)
	return fmt.Sprintf("%d %s", priority, name)
}

// formatTXT formats TXT record data
func formatTXT(rdata []byte) string {
	var txts []string
	for i := 0; i < len(rdata); {
		l := int(rdata[i])
		if i+1+l > len(rdata) {
			break
		}
		txts = append(txts, string(rdata[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(txts, " ")
}

// formatSVCB formats HTTPS/SVCB record data
func formatSVCB(rdata, fullMsg []byte, rdataOffset int) string {
	// HTTPS/SVCB record format: priority (2 bytes) + target name + params
	if len(rdata) < 2 {
		return ""
	}

	priority := binary.BigEndian.Uint16(rdata[0:2])
	var target string
	var paramsStart int

	if len(fullMsg) > 0 {
		name, endOffset, err := parseName(fullMsg, rdataOffset+2)
		if err == nil {
			target = name
			// Calculate parameter start position relative to rdata
			paramsStart = endOffset - rdataOffset
		}
	}

	if target == "" {
		// Fall back to simple parsing
		name, endOffset, _ := parseNameSimple(rdata, 2)
		target = name
		paramsStart = endOffset
	}

	// Parse SVCB parameters
	if paramsStart < len(rdata) {
		params := parseSVCBParams(rdata[paramsStart:])
		if len(params) > 0 {
			return fmt.Sprintf("%d %s %s", priority, target, strings.Join(params, " "))
		}
	}
	return fmt.Sprintf("%d %s", priority, target)
}

// parseNameSimple parses a domain name simply (handles domain names in Rdata)
func parseNameSimple(data []byte, offset int) (name string, newOffset int, err error) {
	var labels []string

	for offset < len(data) {
		b := data[offset]

		// Handle terminator
		if b == 0 {
			offset++
			break
		}

		// Check for compression pointer (0xC0 = 192)
		if b&0xC0 == 0xC0 {
			// Compression pointer - cannot parse in Rdata context
			// Skip the two bytes of the pointer
			offset += 2
			break
		}

		labelLen := int(b)
		if offset+1+labelLen > len(data) {
			break
		}

		labels = append(labels, string(data[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}

	if len(labels) == 0 {
		return ".", offset, nil
	}

	return strings.Join(labels, ".") + ".", offset, nil
}

// parseSVCBParams parses SVCB/HTTPS record parameters
func parseSVCBParams(data []byte) []string {
	var params []string
	offset := 0

	// SVCB parameter format: 2-byte key + 2-byte length + value
	svcParamKeys := map[uint16]string{
		0: "mandatory",
		1: "alpn",
		2: "no-default-alpn",
		3: "port",
		4: "ipv4hint",
		5: "ech",
		6: "ipv6hint",
	}

	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		value := data[offset : offset+int(length)]
		offset += int(length)

		keyName, ok := svcParamKeys[key]
		if !ok {
			keyName = fmt.Sprintf("key%d", key)
		}

		// Format value
		valueStr := formatSVCBValue(key, value, svcParamKeys)

		if key == 2 { // no-default-alpn has no value
			params = append(params, keyName)
		} else if valueStr != "" {
			params = append(params, fmt.Sprintf("%s=%s", keyName, valueStr))
		}
	}

	return params
}

// formatSVCBValue formats SVCB parameter value
func formatSVCBValue(key uint16, value []byte, svcParamKeys map[uint16]string) string {
	switch key {
	case 0: // mandatory
		return formatMandatory(value, svcParamKeys)
	case 1: // alpn
		return formatALPN(value)
	case 2: // no-default-alpn (no value)
		return ""
	case 3: // port
		if len(value) >= 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(value[0:2]))
		}
	case 4: // ipv4hint
		return formatIPHints(value, 4)
	case 5: // ech
		return base64.StdEncoding.EncodeToString(value)
	case 6: // ipv6hint
		return formatIPHints(value, 16)
	default:
		return fmt.Sprintf("%x", value)
	}
	return ""
}

// formatMandatory formats mandatory parameter
func formatMandatory(value []byte, svcParamKeys map[uint16]string) string {
	var mandatory []string
	for i := 0; i+2 <= len(value); i += 2 {
		mk := binary.BigEndian.Uint16(value[i : i+2])
		if mn, ok := svcParamKeys[mk]; ok {
			mandatory = append(mandatory, mn)
		} else {
			mandatory = append(mandatory, fmt.Sprintf("key%d", mk))
		}
	}
	return strings.Join(mandatory, ",")
}

// formatALPN formats ALPN protocol list
func formatALPN(value []byte) string {
	var alpns []string
	for i := 0; i < len(value); {
		l := int(value[i])
		if i+1+l > len(value) {
			break
		}
		alpns = append(alpns, string(value[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(alpns, ",")
}

// formatIPHints formats IP hints
func formatIPHints(value []byte, ipLen int) string {
	var ips []string
	for i := 0; i+ipLen <= len(value); i += ipLen {
		ips = append(ips, net.IP(value[i:i+ipLen]).String())
	}
	return strings.Join(ips, ",")
}

// EncodeBase64URL Base64 URL-safe encodes data
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL Base64 URL-safe decodes a string
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ExtractQueryName extracts query domain name from DNS message
func ExtractQueryName(data []byte) (string, error) {
	if len(data) < HeaderSize {
		return "", errors.New("message too short")
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 {
		return "", errors.New("no questions")
	}

	name, _, err := parseName(data, HeaderSize)
	if err != nil {
		return "", err
	}

	return name, nil
}

// ExtractQueryType extracts query type from DNS message
func ExtractQueryType(data []byte) (uint16, error) {
	if len(data) < HeaderSize+4 {
		return 0, errors.New("message too short")
	}

	_, offset, err := parseName(data, HeaderSize)
	if err != nil {
		return 0, err
	}

	if offset+2 > len(data) {
		return 0, errors.New("invalid message")
	}

	return binary.BigEndian.Uint16(data[offset : offset+2]), nil
}

// BuildQuery builds a DNS query message
func BuildQuery(name string, qtype uint16) ([]byte, error) {
	return BuildQueryWithOptions(name, qtype, false, false)
}

// QueryOptions DNS query options
type QueryOptions struct {
	CD bool // Disable DNSSEC validation (Checking Disabled)
	DO bool // Include DNSSEC records (DNSSEC OK)
}

// BuildQueryWithOptions builds a DNS query message with options
func BuildQueryWithOptions(name string, qtype uint16, cd, do bool) ([]byte, error) {
	// Calculate total size for preallocation
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	questionLen := 0
	for _, label := range labels {
		if len(label) > 63 {
			return nil, errors.New("label too long")
		}
		questionLen += 1 + len(label)
	}
	questionLen += 1 + 2 + 2 // terminator + type + class

	edns0Len := 0
	if do {
		edns0Len = 11 // OPT record size
	}

	totalLen := 12 + questionLen + edns0Len
	buf := make([]byte, 0, totalLen)

	// Header (12 bytes)
	buf = append(buf, 0x00, 0x01) // ID

	// Flags
	flags := uint16(0x0100) // Recursion Desired
	if cd {
		flags |= 0x0010 // Checking Disabled
	}
	buf = append(buf, byte(flags>>8), byte(flags), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	// ARCOUNT
	if do {
		buf = append(buf, 0x00, 0x01) // ARCOUNT = 1
	} else {
		buf = append(buf, 0x00, 0x00) // ARCOUNT = 0
	}

	// Question
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}

	// End of name, Type and Class
	buf = append(buf, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)

	// EDNS0 OPT record (if DO flag needed)
	if do {
		buf = append(buf, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00)
	}

	return buf, nil
}
