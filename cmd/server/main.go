package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/handler"
	"github.com/lyimoexiao/gin-doh/internal/logger"
	"github.com/lyimoexiao/gin-doh/internal/middleware"
	"github.com/lyimoexiao/gin-doh/internal/proxy"
	"github.com/lyimoexiao/gin-doh/internal/strategy"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

var (
	configPath = flag.String("config", "config.yaml", "配置文件路径")
	version    = "dev"
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	log, err := logger.New(&logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Fields: cfg.Logging.Fields,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Infof("gin-doh %s 启动中...", version)

	// 初始化全局代理
	var globalProxy *proxy.Manager
	if cfg.Upstream.Proxy != nil && cfg.Upstream.Proxy.Enabled {
		globalProxy, err = proxy.NewManager(cfg.Upstream.Proxy)
		if err != nil {
			log.Fatalf("初始化代理失败: %v", err)
		}
		log.Infof("全局代理已启用: %s", cfg.Upstream.Proxy.Address)
	}

	// 创建解析器
	factory := upstream.NewFactory(globalProxy)
	resolvers := make([]upstream.Resolver, 0, len(cfg.Upstream.Servers))
	priorities := make([]int, 0, len(cfg.Upstream.Servers))

	for _, serverCfg := range cfg.Upstream.Servers {
		resolver, err := factory.CreateResolver(&serverCfg)
		if err != nil {
			log.Warnf("创建解析器失败 %s://%s: %v", serverCfg.Protocol, serverCfg.Address, err)
			continue
		}
		resolvers = append(resolvers, resolver)
		priorities = append(priorities, serverCfg.Priority)
		log.Infof("上游解析器: %s", resolver.String())
	}

	if len(resolvers) == 0 {
		log.Fatal("没有可用的上游解析器")
	}

	// 创建选择策略
	var selector strategy.Selector
	switch cfg.Upstream.Strategy {
	case "round-robin":
		selector = strategy.NewRoundRobinSelector(resolvers)
	case "failover":
		selector = strategy.NewFailoverSelector(resolvers, priorities, &cfg.Upstream.HealthCheck)
	case "fastest":
		selector = strategy.NewFastestSelector(resolvers, &cfg.Upstream.FastestConfig)
	default:
		selector = strategy.NewRoundRobinSelector(resolvers)
	}
	log.Infof("上游策略: %s", selector.Name())

	// 创建 DoH 处理器
	dohHandler := handler.NewDoHHandler(selector, log, cfg.Server.RateLimit.MaxQuerySize)

	// 设置 Gin 模式
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建路由
	router := gin.New()
	router.Use(middleware.RecoveryMiddleware(log))
	router.Use(middleware.LoggingMiddleware(log))
	router.Use(middleware.CORSMiddleware())

	// 注册 DNS 查询路径
	for _, path := range cfg.Server.DNSPaths {
		if path.Enabled {
			router.POST(path.Path, dohHandler.Handle)
			router.GET(path.Path, dohHandler.Handle)
			log.Infof("注册 DoH 路径: %s", path.Path)
		}
	}

	// 健康检查
	router.GET("/health", dohHandler.HandleHealthCheck)

	// 创建 HTTP 服务器
	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 启动服务器
	go func() {
		var err error
		if cfg.Server.TLS.Enabled {
			log.Infof("HTTPS 服务器启动，监听 %s", cfg.Server.Listen)
			err = srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			log.Infof("HTTP 服务器启动，监听 %s", cfg.Server.Listen)
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("正在关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("服务器关闭错误: %v", err)
	}

	log.Info("服务器已关闭")
}
