package dns

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNS 消息相关常量
const (
	HeaderSize = 12

	// DNS 记录类型
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

	// DNS 响应码
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

// Header DNS 消息头
type Header struct {
	ID      uint16
	Flags   uint16
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

// Question DNS 问题
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord DNS 资源记录
type ResourceRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Rdata  []byte
	RdataStr string // 用于 JSON 输出
}

// Message DNS 消息
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
	Authority []ResourceRecord
	Additional []ResourceRecord
}

// RcodeToString 响应码转字符串
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

// TypeToString 类型转字符串
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
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// StringToType 字符串转类型
func StringToType(s string) uint16 {
	switch strings.ToUpper(s) {
	case "A":
		return TypeA
	case "AAAA":
		return TypeAAAA
	case "CNAME":
		return TypeCNAME
	case "MX":
		return TypeMX
	case "TXT":
		return TypeTXT
	case "NS":
		return TypeNS
	case "PTR":
		return TypePTR
	case "SOA":
		return TypeSOA
	case "SRV":
		return TypeSRV
	case "CAA":
		return TypeCAA
	default:
		return 0
	}
}

// ParseMessage 解析 DNS 消息
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
	}

	offset := HeaderSize

	// 解析问题
	for i := uint16(0); i < msg.Header.Qdcount; i++ {
		q, newOffset, err := parseQuestion(data, offset)
		if err != nil {
			return nil, err
		}
		msg.Questions = append(msg.Questions, q)
		offset = newOffset
	}

	// 解析回答
	for i := uint16(0); i < msg.Header.Ancount; i++ {
		rr, newOffset, err := parseResourceRecord(data, offset)
		if err != nil {
			return nil, err
		}
		msg.Answers = append(msg.Answers, *rr)
		offset = newOffset
	}

	return msg, nil
}

// parseQuestion 解析 DNS 问题
func parseQuestion(data []byte, offset int) (Question, int, error) {
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

// parseResourceRecord 解析资源记录
func parseResourceRecord(data []byte, offset int) (*ResourceRecord, int, error) {
	name, newOffset, err := parseName(data, offset)
	if err != nil {
		return nil, 0, err
	}

	if newOffset+10 > len(data) {
		return nil, 0, errors.New("invalid resource record format")
	}

	rr := &ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
		TTL:   binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
	}

	rdlength := binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10])
	rr.Rdata = make([]byte, rdlength)
	copy(rr.Rdata, data[newOffset+10:newOffset+10+int(rdlength)])
	rr.RdataStr = formatRdata(rr.Type, rr.Rdata)

	return rr, newOffset + 10 + int(rdlength), nil
}

// parseName 解析域名（支持压缩）
func parseName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	jumped := false
	returnOffset := offset

	for {
		if offset >= len(data) {
			return "", 0, errors.New("invalid name")
		}

		b := data[offset]

		// 检查指针
		if b&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, errors.New("invalid pointer")
			}

			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)

			if visited[pointer] {
				return "", 0, errors.New("circular pointer")
			}
			visited[pointer] = true

			// 如果是第一次跳转，记录返回位置
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
			offset++ // 跳过结束符
			break
		}

		labelLen := int(b)
		if offset+1+labelLen > len(data) {
			return "", 0, errors.New("invalid label")
		}

		labels = append(labels, string(data[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}

	// 如果跳转过，返回跳转前的位置；否则返回当前位置
	if jumped {
		return strings.Join(labels, ".") + ".", returnOffset, nil
	}
	return strings.Join(labels, ".") + ".", offset, nil
}

// formatRdata 格式化 Rdata 为字符串
func formatRdata(rrtype uint16, rdata []byte) string {
	switch rrtype {
	case TypeA:
		if len(rdata) == 4 {
			return net.IP(rdata).String()
		}
	case TypeAAAA:
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	case TypeCNAME, TypeNS, TypePTR:
		name, _, _ := parseName(append([]byte{byte(len(rdata))}, rdata...), 0)
		return name
	case TypeMX:
		if len(rdata) >= 3 {
			priority := binary.BigEndian.Uint16(rdata[0:2])
			name, _, _ := parseName(append([]byte{byte(len(rdata) - 2)}, rdata[2:]...), 0)
			return fmt.Sprintf("%d %s", priority, name)
		}
	case TypeTXT:
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
	return fmt.Sprintf("%x", rdata)
}

// EncodeBase64URL Base64 URL 安全编码
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL Base64 URL 安全解码
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ExtractQueryName 从 DNS 消息中提取查询域名
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

// ExtractQueryType 从 DNS 消息中提取查询类型
func ExtractQueryType(data []byte) (uint16, error) {
	if len(data) < HeaderSize+4 {
		return 0, errors.New("message too short")
	}

	name, offset, err := parseName(data, HeaderSize)
	if err != nil {
		return 0, err
	}

	_ = name
	if offset+2 > len(data) {
		return 0, errors.New("invalid message")
	}

	return binary.BigEndian.Uint16(data[offset : offset+2]), nil
}

// BuildQuery 构建 DNS 查询消息
func BuildQuery(name string, qtype uint16) ([]byte, error) {
	var buf []byte

	// Header (12 bytes)
	buf = append(buf, 0x00, 0x01) // ID
	buf = append(buf, 0x01, 0x00) // Flags: Recursion Desired
	buf = append(buf, 0x00, 0x01) // QDCOUNT
	buf = append(buf, 0x00, 0x00) // ANCOUNT
	buf = append(buf, 0x00, 0x00) // NSCOUNT
	buf = append(buf, 0x00, 0x00) // ARCOUNT

	// Question
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if len(label) > 63 {
			return nil, errors.New("label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // End of name

	// Type
	buf = append(buf, byte(qtype>>8), byte(qtype))
	// Class (IN = 1)
	buf = append(buf, 0x00, 0x01)

	return buf, nil
}
