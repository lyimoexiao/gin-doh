// Package main provides the gin-doh DNS-over-HTTPS server.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/ech"
	"github.com/lyimoexiao/gin-doh/internal/handler"
	"github.com/lyimoexiao/gin-doh/internal/logger"
	"github.com/lyimoexiao/gin-doh/internal/middleware"
	"github.com/lyimoexiao/gin-doh/internal/proxy"
	"github.com/lyimoexiao/gin-doh/internal/strategy"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// Build information (injected via ldflags at build time)
var (
	version   = "dev"
	gitCommit = "unknown"
	buildTime = "unknown"
	goVersion = "unknown"
)

var configPath = flag.String("config", "config.yaml", "path to configuration file")

func printVersion() {
	fmt.Printf("gin-doh %s\n", version)
	fmt.Printf("  Git commit: %s\n", gitCommit)
	fmt.Printf("  Build time: %s\n", buildTime)
	fmt.Printf("  Go version: %s\n", goVersion)
}

func main() {
	flag.Parse()

	// Print version and build info
	printVersion()
	fmt.Println()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	log, err := logger.New(&logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Fields: cfg.Logging.Fields,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() {
		if syncErr := log.Sync(); syncErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to sync logger: %v\n", syncErr)
		}
	}()

	log.Infof("gin-doh %s starting...", version)

	// Initialize components
	globalProxy, err := initProxy(cfg, log)
	if err != nil {
		return err
	}

	globalECHConfig, echConfigAvailable, err := initECHConfig(cfg, log)
	if err != nil {
		return err
	}

	// Create resolvers
	resolvers, priorities, err := createResolvers(cfg, globalProxy, globalECHConfig, echConfigAvailable, log)
	if err != nil {
		return err
	}

	// Create selector strategy
	selector := createSelector(cfg, resolvers, priorities)
	log.Infof("Upstream strategy: %s", selector.Name())

	// Create DoH handler
	dohHandler := handler.NewDoHHandler(selector, log, cfg.Server.RateLimit.MaxQuerySize)

	// Setup and run server
	return runServer(cfg, dohHandler, log)
}

func initProxy(cfg *config.Config, log *logger.Logger) (*proxy.Manager, error) {
	if cfg.Upstream.Proxy == nil || !cfg.Upstream.Proxy.Enabled {
		return nil, nil
	}
	pm, err := proxy.NewManager(cfg.Upstream.Proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize proxy: %w", err)
	}
	log.Infof("Global proxy enabled: %s", cfg.Upstream.Proxy.Address)
	return pm, nil
}

func initECHConfig(cfg *config.Config, log *logger.Logger) (*ech.ClientECHConfig, bool, error) {
	if cfg.Server.TLS.ECH.ConfigListFile == "" {
		return nil, false, nil
	}

	globalECHConfig := ech.NewClientECHConfig()
	if err := globalECHConfig.LoadConfigListFromFile(cfg.Server.TLS.ECH.ConfigListFile); err != nil {
		log.Warnf("Failed to load global ECH config: %v", err)
		return nil, false, nil
	}
	log.Info("Global ECH client config loaded")
	return globalECHConfig, true, nil
}

func createResolvers(cfg *config.Config, globalProxy *proxy.Manager, globalECHConfig *ech.ClientECHConfig, echConfigAvailable bool, log *logger.Logger) ([]upstream.Resolver, []int, error) {
	forceEncrypted := cfg.Server.TLS.ECH.Enabled && cfg.Server.TLS.ECH.ForceEncryptedUpstream
	if forceEncrypted {
		log.Info("ECH mode enabled, forcing encrypted upstream (DoH/DoT)")
	}

	factory := upstream.NewFactory(globalProxy,
		upstream.WithForceEncrypted(forceEncrypted),
		upstream.WithECHAvailable(echConfigAvailable),
	)

	resolvers := make([]upstream.Resolver, 0, len(cfg.Upstream.Servers))
	priorities := make([]int, 0, len(cfg.Upstream.Servers))

	for _, serverCfg := range cfg.Upstream.Servers {
		resolver, err := factory.CreateResolverWithECH(&serverCfg, globalECHConfig)
		if err != nil {
			log.Warnf("Failed to create resolver %s://%s: %v", serverCfg.Protocol, serverCfg.Address, err)
			continue
		}
		resolvers = append(resolvers, resolver)
		priorities = append(priorities, serverCfg.Priority)
		log.Infof("Upstream resolver: %s", resolver.String())
	}

	if len(resolvers) == 0 {
		return nil, nil, fmt.Errorf("no upstream resolvers available")
	}

	return resolvers, priorities, nil
}

func createSelector(cfg *config.Config, resolvers []upstream.Resolver, priorities []int) strategy.Selector {
	switch cfg.Upstream.Strategy {
	case "failover":
		return strategy.NewFailoverSelector(resolvers, priorities, &cfg.Upstream.HealthCheck)
	case "fastest":
		return strategy.NewFastestSelector(resolvers, &cfg.Upstream.FastestConfig)
	default:
		return strategy.NewRoundRobinSelector(resolvers)
	}
}

func runServer(cfg *config.Config, dohHandler *handler.DoHHandler, log *logger.Logger) error {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	// Real IP middleware (must be before other middlewares that use ClientIP)
	if len(cfg.Server.TrustedProxies) > 0 {
		router.Use(middleware.RealIPMiddleware(cfg.Server.TrustedProxies))
		log.Infof("Trusted proxies configured: %v", cfg.Server.TrustedProxies)
	}

	router.Use(middleware.RecoveryMiddleware(log))
	router.Use(middleware.LoggingMiddleware(log))
	router.Use(middleware.CORSMiddleware())

	// Register DNS query paths
	for _, path := range cfg.Server.DNSPaths {
		if path.Enabled {
			router.POST(path.Path, dohHandler.Handle)
			router.GET(path.Path, dohHandler.Handle)
			log.Infof("Registered DoH path: %s", path.Path)
		}
	}

	// Health check endpoint
	router.GET("/health", dohHandler.HandleHealthCheck)

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- startServer(cfg, srv, log)
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server startup failed: %w", err)
		}
	case <-quit:
	}

	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("Server shutdown error: %v", err)
	}

	log.Info("Server stopped")
	return nil
}

func startServer(cfg *config.Config, srv *http.Server, log *logger.Logger) error {
	if cfg.Server.TLS.Enabled {
		return startTLSServer(cfg, srv, log)
	}

	log.Infof("HTTP server started, listening on %s", cfg.Server.Listen)
	return srv.ListenAndServe()
}

func startTLSServer(cfg *config.Config, srv *http.Server, log *logger.Logger) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Configure server-side ECH
	if cfg.Server.TLS.ECH.Enabled {
		tlsConfig, err = configureECH(cfg, tlsConfig, log)
		if err != nil {
			log.Warnf("Failed to configure ECH: %v", err)
		}
	}

	srv.TLSConfig = tlsConfig
	log.Infof("HTTPS server started, listening on %s", cfg.Server.Listen)
	return srv.ListenAndServeTLS("", "")
}

func configureECH(cfg *config.Config, tlsConfig *tls.Config, log *logger.Logger) (*tls.Config, error) {
	serverECH, err := setupServerECH(&cfg.Server.TLS.ECH, log)
	if err != nil {
		return tlsConfig, err
	}
	if serverECH == nil {
		return tlsConfig, nil
	}

	newTLSConfig, err := serverECH.GetTLSConfig(tlsConfig)
	if err != nil {
		return tlsConfig, err
	}

	log.Info("Server-side ECH enabled")
	return newTLSConfig, nil
}

// setupServerECH configures server-side ECH
func setupServerECH(cfg *config.ECHConfig, log *logger.Logger) (*ech.ServerECHConfig, error) {
	serverECH := ech.NewServerECHConfig(cfg.PublicName)

	// Load from config file if provided
	if cfg.ConfigFile != "" {
		if err := serverECH.LoadConfigListFromFile(cfg.ConfigFile); err != nil {
			return nil, fmt.Errorf("failed to load ECH config file: %w", err)
		}
	}

	// Load private key if provided
	if cfg.KeyFile != "" {
		// Try to load private key (assuming config ID 0)
		key, err := ech.LoadPrivateKey(cfg.KeyFile, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to load ECH private key: %w", err)
		}
		if err := serverECH.AddKey(key); err != nil {
			return nil, fmt.Errorf("failed to add ECH key: %w", err)
		}
	}

	// Load retry config if provided
	if cfg.RetryConfigFile != "" {
		if err := serverECH.LoadRetryConfigFromFile(cfg.RetryConfigFile); err != nil {
			log.Warnf("Failed to load ECH retry config: %v", err)
		}
	}

	return serverECH, nil
}
