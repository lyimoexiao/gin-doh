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

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(&logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Fields: cfg.Logging.Fields,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Infof("gin-doh %s starting...", version)

	// Initialize global proxy
	var globalProxy *proxy.Manager
	if cfg.Upstream.Proxy != nil && cfg.Upstream.Proxy.Enabled {
		globalProxy, err = proxy.NewManager(cfg.Upstream.Proxy)
		if err != nil {
			log.Fatalf("Failed to initialize proxy: %v", err)
		}
		log.Infof("Global proxy enabled: %s", cfg.Upstream.Proxy.Address)
	}

	// Initialize global ECH client config (for upstream DoH connections)
	var globalECHConfig *ech.ClientECHConfig
	echConfigAvailable := false
	if cfg.Server.TLS.ECH.ConfigListFile != "" {
		globalECHConfig = ech.NewClientECHConfig()
		if err := globalECHConfig.LoadConfigListFromFile(cfg.Server.TLS.ECH.ConfigListFile); err != nil {
			log.Warnf("Failed to load global ECH config: %v", err)
			globalECHConfig = nil
		} else {
			log.Info("Global ECH client config loaded")
			echConfigAvailable = true
		}
	}

	// Determine if encrypted upstream is forced
	forceEncrypted := cfg.Server.TLS.ECH.Enabled && cfg.Server.TLS.ECH.ForceEncryptedUpstream
	if forceEncrypted {
		log.Info("ECH mode enabled, forcing encrypted upstream (DoH/DoT)")
	}

	// Create resolvers
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
		log.Fatal("No upstream resolvers available")
	}

	// Create selector strategy
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
	log.Infof("Upstream strategy: %s", selector.Name())

	// Create DoH handler
	dohHandler := handler.NewDoHHandler(selector, log, cfg.Server.RateLimit.MaxQuerySize)

	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
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

	// Start server
	go func() {
		var err error
		if cfg.Server.TLS.Enabled {
			// Configure TLS
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1"},
			}

			// Load certificate
			cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			if err != nil {
				log.Fatalf("Failed to load certificate: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}

			// Configure server-side ECH
			if cfg.Server.TLS.ECH.Enabled {
				serverECH, err := setupServerECH(&cfg.Server.TLS.ECH, log)
				if err != nil {
					log.Warnf("Failed to configure ECH: %v", err)
				} else if serverECH != nil {
					tlsConfig, err = serverECH.GetTLSConfig(tlsConfig)
					if err != nil {
						log.Warnf("Failed to apply ECH config: %v", err)
					} else {
						log.Info("Server-side ECH enabled")
					}
				}
			}

			srv.TLSConfig = tlsConfig
			log.Infof("HTTPS server started, listening on %s", cfg.Server.Listen)
			err = srv.ListenAndServeTLS("", "") // Certificate already configured in TLSConfig
		} else {
			log.Infof("HTTP server started, listening on %s", cfg.Server.Listen)
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server startup failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("Server shutdown error: %v", err)
	}

	log.Info("Server stopped")
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
