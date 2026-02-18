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
	TypeOPT   = 41 // EDNS0 OPT record

	// DNS response codes
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5

	// EDNS0 option codes
	EDNS0OptionECS = 8 // EDNS Client Subnet (RFC 7871)

	// EDNS0 constants
	EDNS0UDPSize = 4096
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
		num, err := strconv.Atoi(s[4:])
		if err == nil && num >= 0 && num <= 65535 {
			return uint16(num)
		}
		return 0
	}

	// Try parsing pure number format (e.g., "65")
	num, err := strconv.Atoi(s)
	if err == nil && num > 0 && num <= 65535 {
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
	CD  bool   // Disable DNSSEC validation (Checking Disabled)
	DO  bool   // Include DNSSEC records (DNSSEC OK)
	ECS string // EDNS Client Subnet (e.g., "116.153.81.41/24")
}

// BuildQueryWithOptions builds a DNS query message with options (legacy signature)
func BuildQueryWithOptions(name string, qtype uint16, cd, do bool) ([]byte, error) {
	return BuildQueryWithOpts(name, qtype, QueryOptions{CD: cd, DO: do})
}

// BuildQueryWithOpts builds a DNS query message with QueryOptions
func BuildQueryWithOpts(name string, qtype uint16, opts QueryOptions) ([]byte, error) {
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

	// Calculate EDNS0 size
	edns0Len := 0
	needEDNS := opts.DO || opts.ECS != ""

	if needEDNS {
		edns0Len = 11 // Base OPT record size
		if opts.ECS != "" {
			// ECS option: 2 bytes code + 2 bytes length + ECS data
			ecsData, err := parseECS(opts.ECS)
			if err != nil {
				return nil, fmt.Errorf("invalid ECS: %w", err)
			}
			edns0Len += 4 + len(ecsData) // option code + length + data
		}
	}

	totalLen := 12 + questionLen + edns0Len
	buf := make([]byte, 0, totalLen)

	// Header (12 bytes)
	buf = append(buf, 0x00, 0x01) // ID

	// Flags
	flags := uint16(0x0100) // Recursion Desired
	if opts.CD {
		flags |= 0x0010 // Checking Disabled
	}
	buf = append(buf, byte(flags>>8), byte(flags), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	// ARCOUNT
	if needEDNS {
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

	// EDNS0 OPT record
	if needEDNS {
		// Calculate total RDATA length
		rdataLen := 0
		if opts.DO {
			rdataLen += 4 // DO flag is in TTL, but we need to include options
		}
		if opts.ECS != "" {
			ecsData, _ := parseECS(opts.ECS)
			rdataLen += 4 + len(ecsData) // option code + length + data
		}

		// OPT record: name(root) + type + udp_size + flags + rdata_len
		buf = append(buf, 0x00, 0x00, 0x29, 0x10, 0x00)
		// Extended RCODE and flags (DO flag in high bit)
		if opts.DO {
			buf = append(buf, 0x00, 0x00, 0x80, 0x00) // DO flag set
		} else {
			buf = append(buf, 0x00, 0x00, 0x00, 0x00)
		}
		// RDATA length
		buf = append(buf, byte(rdataLen>>8), byte(rdataLen))

		// Add ECS option if provided
		if opts.ECS != "" {
			ecsData, _ := parseECS(opts.ECS)
			// Option code + length + data
			buf = append(buf, 0x00, 0x08, byte(len(ecsData)>>8), byte(len(ecsData)))
			buf = append(buf, ecsData...)
		}
	}

	return buf, nil
}

// parseECS parses ECS string like "116.153.81.41/24" and returns ECS option data
// Format: FAMILY (2 bytes) + SOURCE PREFIX-LENGTH (1 byte) + SCOPE PREFIX-LENGTH (1 byte) + ADDRESS (variable)
func parseECS(ecs string) ([]byte, error) {
	parts := strings.Split(ecs, "/")
	if len(parts) != 2 {
		return nil, errors.New("invalid ECS format, expected IP/PREFIX")
	}

	ipStr := parts[0]
	prefixLen, err := strconv.Atoi(parts[1])
	if err != nil || prefixLen < 0 || prefixLen > 255 {
		return nil, errors.New("invalid prefix length")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}

	var family uint16
	var addrBytes []byte

	if ip.To4() != nil {
		// IPv4
		family = 1
		addrBytes = ip.To4()
		if prefixLen < 0 || prefixLen > 32 {
			return nil, errors.New("IPv4 prefix length must be 0-32")
		}
	} else {
		// IPv6
		family = 2
		addrBytes = ip.To16()
		if prefixLen < 0 || prefixLen > 128 {
			return nil, errors.New("IPv6 prefix length must be 0-128")
		}
	}

	// Calculate how many address bytes to include
	// Round up to next byte boundary
	addrLen := (prefixLen + 7) / 8
	if addrLen > len(addrBytes) {
		addrLen = len(addrBytes)
	}

	// Build ECS option data
	result := make([]byte, 0, 4+addrLen)
	// Family (2 bytes) + Source prefix length (1 byte) + Scope prefix length (1 byte, always 0)
	result = append(result, byte(family>>8), byte(family), byte(prefixLen), 0x00)
	// Address (truncated to prefix bytes)
	result = append(result, addrBytes[:addrLen]...)

	return result, nil
}

// ClientIPToECS converts client IP to ECS string format
// Returns empty string if the IP is private, loopback, invalid, or should not be forwarded
// For IPv4: returns "x.x.x.x/32"
// For IPv6: returns "x:x:x:x:x:x:x:x/128"
func ClientIPToECS(clientIP string) string {
	if clientIP == "" {
		return ""
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ""
	}

	// Skip loopback addresses
	if ip.IsLoopback() {
		return ""
	}

	// Skip private/local addresses
	if ip.IsPrivate() {
		return ""
	}

	// Skip link-local addresses
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ""
	}

	// Skip unspecified address (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return ""
	}

	// Check for IPv4-mapped IPv6 addresses
	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4 address - use /32 prefix
		return ip4.String() + "/32"
	}

	// IPv6 address - use /128 prefix
	return ip.String() + "/128"
}

// InjectECS injects ECS option into an existing DNS query
// If the query already has EDNS0 with ECS, it will be replaced
// If the query has no EDNS0, it will be added
// Returns the modified query or the original if no modification needed
func InjectECS(query []byte, ecs string) ([]byte, error) {
	if ecs == "" {
		return query, nil
	}

	if len(query) < HeaderSize {
		return nil, errors.New("query too short")
	}

	ecsData, err := parseECS(ecs)
	if err != nil {
		return nil, err
	}

	// Find OPT record in additional section
	optOffset, err := findOPTRecord(query)
	if err != nil {
		return nil, err
	}

	if optOffset >= 0 {
		// Modify existing OPT record to add/replace ECS option
		return injectECSToOPT(query, optOffset, ecsData)
	}

	// Add new OPT record with ECS
	return addOPTWithECS(query, ecsData)
}

// HasECS checks if the DNS query already contains an ECS option
// Returns true if ECS is present in the query
func HasECS(query []byte) bool {
	if len(query) < HeaderSize {
		return false
	}

	// Find OPT record
	optOffset, err := findOPTRecord(query)
	if err != nil || optOffset < 0 {
		return false
	}

	// Parse OPT RDATA to check for ECS option
	rdataLenOffset := optOffset + 1 + 2 + 2 + 4
	if rdataLenOffset+2 > len(query) {
		return false
	}

	rdataLen := int(binary.BigEndian.Uint16(query[rdataLenOffset : rdataLenOffset+2]))
	rdataStart := rdataLenOffset + 2
	rdataEnd := rdataStart + rdataLen

	if rdataEnd > len(query) {
		return false
	}

	// Scan options for ECS
	offset := rdataStart
	for offset+4 <= rdataEnd {
		optCode := binary.BigEndian.Uint16(query[offset : offset+2])
		optLen := int(binary.BigEndian.Uint16(query[offset+2 : offset+4]))

		if optCode == EDNS0OptionECS {
			return true
		}

		offset += 4 + optLen
	}

	return false
}

// findOPTRecord finds the OPT record offset in the additional section
// Returns -1 if not found, or the offset if found
func findOPTRecord(query []byte) (int, error) {
	arcount := int(binary.BigEndian.Uint16(query[10:12]))
	if arcount == 0 {
		return -1, nil
	}

	// Parse question section to find additional section start
	offset := skipQuestionSection(query)
	if offset < 0 {
		return -1, errors.New("invalid query format")
	}

	// Search for OPT record in additional section
	for i := 0; i < arcount; i++ {
		if offset >= len(query) {
			break
		}

		// Check for root name (OPT record starts with 0x00)
		if query[offset] == 0x00 && offset+3 < len(query) {
			rrType := binary.BigEndian.Uint16(query[offset+1 : offset+3])
			if rrType == TypeOPT {
				return offset, nil
			}
		}

		// Skip this record
		nextOffset, err := skipResourceRecord(query, offset)
		if err != nil {
			return -1, err
		}
		offset = nextOffset
	}

	return -1, nil
}

// skipQuestionSection skips the question section and returns the offset after it
func skipQuestionSection(query []byte) int {
	qdcount := int(binary.BigEndian.Uint16(query[4:6]))
	offset := HeaderSize

	for i := 0; i < qdcount; i++ {
		for offset < len(query) {
			b := query[offset]
			if b == 0 {
				offset += 5 // null terminator + type + class
				break
			}
			offset += 1 + int(b)
		}
	}

	return offset
}

// skipResourceRecord skips a resource record and returns the next offset
func skipResourceRecord(query []byte, offset int) (int, error) {
	if offset >= len(query) {
		return -1, errors.New("offset out of bounds")
	}

	// Skip name (root or compressed)
	if query[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(query) && query[offset] != 0 {
			offset += 1 + int(query[offset])
		}
		offset++ // null terminator
	}

	// Skip type, class, TTL (10 bytes) + rdlength + rdata
	if offset+10 > len(query) {
		return -1, errors.New("invalid resource record")
	}

	rdlength := int(binary.BigEndian.Uint16(query[offset+8 : offset+10]))
	return offset + 10 + rdlength, nil
}

// injectECSToOPT injects ECS into existing OPT record
func injectECSToOPT(query []byte, optOffset int, ecsData []byte) ([]byte, error) {
	// OPT record format: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA
	// We need to read current RDATA and add ECS option

	// Skip name (0x00), type (2), class (2), TTL (4)
	rdataLenOffset := optOffset + 1 + 2 + 2 + 4
	if rdataLenOffset+2 > len(query) {
		return nil, errors.New("invalid OPT record")
	}

	oldRdataLen := int(binary.BigEndian.Uint16(query[rdataLenOffset : rdataLenOffset+2]))
	rdataStart := rdataLenOffset + 2
	rdataEnd := rdataStart + oldRdataLen

	// Parse existing options to check for ECS
	newRdata := make([]byte, 0, oldRdataLen+4+len(ecsData))
	offset := rdataStart
	hasECS := false

	for offset+4 <= rdataEnd {
		optCode := binary.BigEndian.Uint16(query[offset : offset+2])
		optLen := int(binary.BigEndian.Uint16(query[offset+2 : offset+4]))

		if optCode == EDNS0OptionECS {
			// Found existing ECS, skip it and add new one
			hasECS = true
			// Add new ECS option: code + length + data
			newRdata = append(newRdata, 0x00, 0x08, byte(len(ecsData)>>8), byte(len(ecsData)))
			newRdata = append(newRdata, ecsData...)
			offset += 4 + optLen
		} else {
			// Copy other options as-is
			newRdata = append(newRdata, query[offset:offset+4+optLen]...)
			offset += 4 + optLen
		}
	}

	if !hasECS {
		// No existing ECS, add it
		newRdata = append(newRdata, query[rdataStart:rdataEnd]...)
		// Add ECS option: code + length + data
		newRdata = append(newRdata, 0x00, 0x08, byte(len(ecsData)>>8), byte(len(ecsData)))
		newRdata = append(newRdata, ecsData...)
	}

	// Build new query
	result := make([]byte, 0, len(query)-oldRdataLen+len(newRdata))
	result = append(result, query[:rdataLenOffset]...)
	// Write new RDLEN
	result = append(result, byte(len(newRdata)>>8), byte(len(newRdata)))
	// Write new RDATA
	result = append(result, newRdata...)

	return result, nil
}

// addOPTWithECS adds new OPT record with ECS to query
func addOPTWithECS(query, ecsData []byte) ([]byte, error) {
	// Build OPT RDATA with ECS option: code + length + data
	optRdata := make([]byte, 0, 4+len(ecsData))
	optRdata = append(optRdata, 0x00, 0x08, byte(len(ecsData)>>8), byte(len(ecsData)))
	optRdata = append(optRdata, ecsData...)

	// OPT record: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA
	optRecord := make([]byte, 0, 11+len(optRdata))
	// Root name + Type OPT(41) + UDP size(4096) + Extended RCODE/flags + RDLEN
	optRecord = append(optRecord, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, byte(len(optRdata)>>8), byte(len(optRdata)))
	// RDATA
	optRecord = append(optRecord, optRdata...)

	// Build new query
	result := make([]byte, 0, len(query)+len(optRecord))
	result = append(result, query...)

	// Update ARCOUNT
	arcount := binary.BigEndian.Uint16(result[10:12])
	binary.BigEndian.PutUint16(result[10:12], arcount+1)

	// Append OPT record
	result = append(result, optRecord...)

	return result, nil
}
