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
	TypeHTTPS = 65  // HTTPS SVCB 记录 (RFC 9460)
	TypeSVCB  = 64  // SVCB 记录 (RFC 9460)

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
	rawData   []byte // 保存原始数据用于解析压缩指针
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
	case TypeHTTPS:
		return "HTTPS"
	case TypeSVCB:
		return "SVCB"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// StringToType 字符串转类型
func StringToType(s string) uint16 {
	upper := strings.ToUpper(s)
	switch upper {
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
	case "HTTPS":
		return TypeHTTPS
	case "SVCB":
		return TypeSVCB
	default:
		// 尝试解析 TYPExxx 格式
		if len(upper) > 4 && upper[:4] == "TYPE" {
			var num uint16
			fmt.Sscanf(s[4:], "%d", &num)
			return num
		}
		// 尝试解析纯数字格式 (如 "65")
		var num uint16
		if n, _ := fmt.Sscanf(s, "%d", &num); n == 1 && num > 0 {
			return num
		}
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
		rawData: data, // 保存原始数据
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
		rr, newOffset, err := parseResourceRecordWithContext(data, offset, msg.rawData)
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

// parseResourceRecord 解析资源记录 (不包含压缩指针上下文)
func parseResourceRecord(data []byte, offset int) (*ResourceRecord, int, error) {
	return parseResourceRecordWithContext(data, offset, data)
}

// parseResourceRecordWithContext 解析资源记录 (带完整消息上下文)
func parseResourceRecordWithContext(data []byte, offset int, fullMsg []byte) (*ResourceRecord, int, error) {
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
	rdataStart := newOffset + 10
	rr.Rdata = make([]byte, rdlength)
	copy(rr.Rdata, data[rdataStart:rdataStart+int(rdlength)])
	
	// 使用完整消息数据格式化 Rdata，支持压缩指针
	rr.RdataStr = formatRdataWithContext(rr.Type, rr.Rdata, fullMsg, rdataStart)

	return rr, rdataStart + int(rdlength), nil
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

// formatRdata 格式化 Rdata 为字符串 (无消息上下文版本)

func formatRdata(rrtype uint16, rdata []byte) string {

	return formatRdataWithContext(rrtype, rdata, nil, 0)

}



// formatRdataWithMessage 格式化 Rdata 为字符串 (带消息上下文支持压缩指针)

func formatRdataWithMessage(rrtype uint16, rdata []byte, fullMsg []byte) string {

	return formatRdataWithContext(rrtype, rdata, fullMsg, 0)

}



// formatRdataWithContext 格式化 Rdata 为字符串 (完整版本)

func formatRdataWithContext(rrtype uint16, rdata []byte, fullMsg []byte, rdataOffset int) string {

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

		if len(rdata) > 0 {

			// 如果有完整消息，尝试使用压缩指针解析

			if fullMsg != nil && len(fullMsg) > 0 {

				name, _, err := parseName(fullMsg, rdataOffset)

				if err == nil && name != "." {

					return name

				}

			}

			// 回退到简单解析

			name, _, err := parseNameSimple(rdata, 0)

			if err == nil && name != "." {

				return name

			}

		}

	case TypeMX:

		if len(rdata) >= 3 {

			priority := binary.BigEndian.Uint16(rdata[0:2])

			if fullMsg != nil && len(fullMsg) > 0 {

				name, _, err := parseName(fullMsg, rdataOffset+2)

				if err == nil && name != "." {

					return fmt.Sprintf("%d %s", priority, name)

				}

			}

			name, _, _ := parseNameSimple(rdata, 2)

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

						case TypeHTTPS, TypeSVCB:

							// HTTPS/SVCB 记录格式: priority (2 bytes) + target name + params

							// 尝试解析为友好格式

							if len(rdata) >= 2 {

								priority := binary.BigEndian.Uint16(rdata[0:2])

								var target string

								var paramsStart int

								

								if fullMsg != nil && len(fullMsg) > 0 {

									name, endOffset, err := parseName(fullMsg, rdataOffset+2)

									if err == nil {

										target = name

										// 计算参数起始位置相对于 rdata 的偏移

										// endOffset 是完整消息中的位置，减去 rdataOffset 得到 RDATA 中的偏移

										paramsStart = endOffset - rdataOffset

									}

								}

								

								if target == "" {

									// 回退到简单解析

									name, endOffset, _ := parseNameSimple(rdata, 2)

									target = name

									paramsStart = endOffset

								}

					

					// 解析 SVCB 参数

					if paramsStart < len(rdata) {

						params := parseSVCBParams(rdata[paramsStart:])

						if len(params) > 0 {

							return fmt.Sprintf("%d %s %s", priority, target, strings.Join(params, " "))

						}

					}

					return fmt.Sprintf("%d %s", priority, target)

				}

				// 返回空字符串，让 JSON 格式化器使用 RFC 8427 格式

				return ""

	}

	return fmt.Sprintf("%x", rdata)

}



// parseNameSimple 简单域名解析 (处理 Rdata 中的域名)

func parseNameSimple(data []byte, offset int) (string, int, error) {

	var labels []string



	for {

		if offset >= len(data) {

			break

		}



		b := data[offset]



		// 处理结束符

		if b == 0 {

			offset++

			break

		}



		// 检查压缩指针 (0xC0 = 192)

		if b&0xC0 == 0xC0 {

			// 压缩指针 - 在 Rdata 上下文中无法解析

			// 跳过指针的两个字节

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



	



	// parseSVCBParams 解析 SVCB/HTTPS 记录的参数



	func parseSVCBParams(data []byte) []string {



		var params []string



		offset := 0



	



		// SVCB 参数格式: 2字节 key + 2字节 length + value



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



	



			// 格式化值



			var valueStr string



			switch key {



			case 0: // mandatory



				// 列出必须的参数键



				var mandatory []string



				for i := 0; i+2 <= len(value); i += 2 {



					mk := binary.BigEndian.Uint16(value[i : i+2])



					if mn, ok := svcParamKeys[mk]; ok {



						mandatory = append(mandatory, mn)



					} else {



						mandatory = append(mandatory, fmt.Sprintf("key%d", mk))



					}



				}



				valueStr = strings.Join(mandatory, ",")



			case 1: // alpn



				// ALPN 协议列表



				var alpns []string



				for i := 0; i < len(value); {



					if i >= len(value) {



						break



					}



					l := int(value[i])



					if i+1+l > len(value) {



						break



					}



					alpns = append(alpns, string(value[i+1:i+1+l]))



					i += 1 + l



				}



				valueStr = strings.Join(alpns, ",")



			case 2: // no-default-alpn (无值)



				valueStr = ""



			case 3: // port



				if len(value) >= 2 {



					valueStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(value[0:2]))



				}



			case 4: // ipv4hint



				var ips []string



				for i := 0; i+4 <= len(value); i += 4 {



					ips = append(ips, net.IP(value[i:i+4]).String())



				}



				valueStr = strings.Join(ips, ",")



			case 5: // ech



				// ECH 配置，使用 Base64 编码



				valueStr = base64.StdEncoding.EncodeToString(value)



			case 6: // ipv6hint



				var ips []string



				for i := 0; i+16 <= len(value); i += 16 {



					ips = append(ips, net.IP(value[i:i+16]).String())



				}



				valueStr = strings.Join(ips, ",")



			default:



				// 未知参数，使用十六进制



				valueStr = fmt.Sprintf("%x", value)



			}



	



			if key == 2 { // no-default-alpn 无值



				params = append(params, keyName)



			} else if valueStr != "" {



				params = append(params, fmt.Sprintf("%s=%s", keyName, valueStr))



			}



		}



	



		return params



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
	return BuildQueryWithOptions(name, qtype, false, false)
}

// QueryOptions DNS 查询选项
type QueryOptions struct {
	CD bool // 禁用 DNSSEC 验证 (Checking Disabled)
	DO bool // 包含 DNSSEC 记录 (DNSSEC OK)
}

// BuildQueryWithOptions 构建 DNS 查询消息（支持选项）
func BuildQueryWithOptions(name string, qtype uint16, cd, do bool) ([]byte, error) {
	var buf []byte

	// Header (12 bytes)
	buf = append(buf, 0x00, 0x01) // ID

	// Flags
	flags := uint16(0x0100) // Recursion Desired
	if cd {
		flags |= 0x0010 // Checking Disabled
	}
	buf = append(buf, byte(flags>>8), byte(flags))

	buf = append(buf, 0x00, 0x01) // QDCOUNT
	buf = append(buf, 0x00, 0x00) // ANCOUNT
	buf = append(buf, 0x00, 0x00) // NSCOUNT

	// ARCOUNT - 如果需要 DO 标志，添加 EDNS0 OPT 记录
	if do {
		buf = append(buf, 0x00, 0x01) // ARCOUNT = 1
	} else {
		buf = append(buf, 0x00, 0x00) // ARCOUNT = 0
	}

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

	// EDNS0 OPT 记录（如果需要 DO 标志）
	if do {
		// OPT 记录名称 (root)
		buf = append(buf, 0x00)
		// Type (OPT = 41)
		buf = append(buf, 0x00, 0x29)
		// UDP payload size (4096)
		buf = append(buf, 0x10, 0x00)
		// Extended RCODE and EDNS0 version (0)
		buf = append(buf, 0x00, 0x00)
		// Z field with DO bit set (0x8000)
		buf = append(buf, 0x80, 0x00)
		// RDATA length (0)
		buf = append(buf, 0x00, 0x00)
	}

	return buf, nil
}
