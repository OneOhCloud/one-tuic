package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/OneOhCloud/one-tuic/internal/config"
	"github.com/OneOhCloud/one-tuic/internal/outbound/tuic"
	"github.com/OneOhCloud/one-tuic/internal/socks5"
	"github.com/google/uuid"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("c", "config.json", "path to configuration file")
	version := flag.Bool("v", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("one-tuic %s (built %s)\n", Version, BuildTime)
		os.Exit(0)
	}

	// Setup logger
	logLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Set log level
	switch cfg.LogLevel {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	}

	logger.Info("starting one-tuic", "version", Version, "server", cfg.Relay.Server)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse UUID
	uuidParsed, err := uuid.Parse(cfg.Relay.UUID)
	if err != nil {
		logger.Error("invalid UUID", "error", err)
		os.Exit(1)
	}

	// Create TUIC outbound
	tuicCfg := tuic.Config{
		Server:         cfg.Relay.Server,
		UUID:           uuidParsed,
		Password:       cfg.Relay.Password,
		UDPRelayMode:   cfg.Relay.UDPRelayMode,
		CongestionCtrl: cfg.Relay.CongestionCtrl,
		ZeroRTT:        cfg.Relay.ZeroRTT,
		DisableSNI:     cfg.Relay.DisableSNI,
		SkipCertVerify: cfg.Relay.SkipCertVerify,
		ALPN:           cfg.Relay.ALPN,
		Timeout:        cfg.Relay.Timeout.Duration,
		Heartbeat:      cfg.Relay.Heartbeat.Duration,
		SendWindow:     cfg.Relay.SendWindow,
		ReceiveWindow:  cfg.Relay.ReceiveWindow,
	}

	tuicOutbound := tuic.New(tuicCfg)
	if err := tuicOutbound.Connect(ctx); err != nil {
		logger.Error("failed to establish TUIC connection", "error", err)
		os.Exit(1)
	}

	logger.Info("TUIC connection established", "server", cfg.Relay.Server)

	// Create and start SOCKS5 server
	socks5Cfg := socks5.Config{
		Addr:          cfg.Local.Server,
		Username:      cfg.Local.Username,
		Password:      cfg.Local.Password,
		MaxPacketSize: cfg.Local.MaxPacketSize,
	}

	socks5Server := socks5.NewServer(socks5Cfg, tuicOutbound, logger)

	if err := socks5Server.Start(); err != nil {
		logger.Error("failed to start SOCKS5 server", "error", err)
		os.Exit(1)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	logger.Info("shutting down...")

	// Graceful shutdown
	socks5Server.Stop()
	tuicOutbound.Close()

	logger.Info("shutdown complete")
}
