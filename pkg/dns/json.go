package dns

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JSONResponse DNS JSON 响应格式 (遵循 Google DoH API 格式)
type JSONResponse struct {
	Status    int           `json:"Status"`
	TC        bool          `json:"TC"`
	RD        bool          `json:"RD"`
	RA        bool          `json:"RA"`
	AD        bool          `json:"AD"`
	CD        bool          `json:"CD"`
	Question  []JSONQuestion `json:"Question,omitempty"`
	Answer    []JSONAnswer   `json:"Answer,omitempty"`
	Authority []JSONAnswer   `json:"Authority,omitempty"`
	Comment   string         `json:"Comment,omitempty"`
}

// JSONQuestion JSON 问题格式
type JSONQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

// JSONAnswer JSON 回答格式
type JSONAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// WireToJSON 将 Wire Format 转换为 JSON 格式
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

	// 转换问题
	for _, q := range msg.Questions {
		resp.Question = append(resp.Question, JSONQuestion{
			Name: q.Name,
			Type: int(q.Type),
		})
	}

	// 转换回答
	for _, a := range msg.Answers {
		// 计算剩余 TTL（简化处理，使用原始 TTL）
		ttl := int(a.TTL)
		if ttl < 0 {
			ttl = 0
		}

		// 格式化 data 字段
		dataStr := a.RdataStr
		
		// 如果解析成功且非空，直接使用
		// 否则使用 RFC 8427 格式
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

// formatUnknownRdata 格式化未知类型的 Rdata (RFC 8427 格式)
func formatUnknownRdata(rdata []byte) string {
	if len(rdata) == 0 {
		return "\\# 0"
	}
	// 使用空格分隔的十六进制格式，与 Cloudflare 保持一致
	return fmt.Sprintf("\\# %d %s", len(rdata), formatHexWithSpaces(rdata))
}

// formatHexWithSpaces 格式化十六进制并用空格分隔
func formatHexWithSpaces(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " ")
}

// ToJSONBytes 转换为 JSON 字节
func (r *JSONResponse) ToJSONBytes() ([]byte, error) {
	return json.Marshal(r)
}

// IsAcceptJSON 检查 Accept 头是否要求 JSON 格式
func IsAcceptJSON(accept string) bool {
	return accept == "application/dns-json" ||
		accept == "application/json"
}

// IsAcceptWireFormat 检查 Accept 头是否要求 Wire Format
func IsAcceptWireFormat(accept string) bool {
	return accept == "application/dns-message" || accept == ""
}

// QueryParams DNS JSON 查询参数
type QueryParams struct {
	Name string
	Type string
	CD   bool // 禁用 DNSSEC
	DO   bool // 包含 DNSSEC 记录
}

// JSONResponseFromError 从错误创建 JSON 响应
func JSONResponseFromError(rcode int, comment string) *JSONResponse {
	return &JSONResponse{
		Status:  rcode,
		Comment: comment,
	}
}

// CurrentTimestamp 获取当前时间戳
func CurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
