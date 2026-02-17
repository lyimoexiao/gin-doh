package strategy

import (
	"context"

	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// Selector 上游服务器选择策略接口
type Selector interface {
	// Select 选择一个上游服务器
	Select(ctx context.Context) (upstream.Resolver, error)

	// ReportSuccess 报告成功
	ReportSuccess(resolver upstream.Resolver)

	// ReportFailure 报告失败
	ReportFailure(resolver upstream.Resolver)

	// Name 返回策略名称
	Name() string
}

// SelectorInfo 选择器信息
type SelectorInfo struct {
	Name      string
	Resolvers []upstream.ResolverInfo
}

// BaseSelector 基础选择器
type BaseSelector struct {
	name      string
	resolvers []upstream.Resolver
}

// Name 返回策略名称
func (s *BaseSelector) Name() string {
	return s.name
}

// Resolvers 返回所有解析器
func (s *BaseSelector) Resolvers() []upstream.Resolver {
	return s.resolvers
}

// ResolverInfo 返回解析器信息
func (s *BaseSelector) ResolverInfo() []upstream.ResolverInfo {
	infos := make([]upstream.ResolverInfo, len(s.resolvers))
	for i, r := range s.resolvers {
		infos[i] = upstream.ResolverInfo{
			Protocol: r.Protocol(),
			Address:  r.Address(),
		}
	}
	return infos
}
