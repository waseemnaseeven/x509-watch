package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"x509-watch/internal/config"
	"x509-watch/internal/infrastructure/certloader"
	"x509-watch/internal/infrastructure/httpserver"
	"x509-watch/internal/infrastructure/log"
	"x509-watch/internal/infrastructure/metrics"
	"x509-watch/internal/usecase"
)

var (
	version  = "dev"
	revision = "unknown"
)

func main() {
	cfg := config.FromFlags()

	logger := log.NewLogger(cfg.LogLevel)

	if err := cfg.Validate(); err != nil {
		logger.Errorf("invalid config: %v", err)
		os.Exit(1)
	}

	metrics.SetBuildInfo(version, revision)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var loader usecase.CertLoader
	if cfg.CertFile != "" {
		logger.Infof("Using file loader for %s", cfg.CertFile)
		loader = certloader.NewFileLoader(cfg.CertFile, logger)
	} else {
		logger.Infof("Using dir loader for %s", cfg.CertDir)
		loader = certloader.NewDirLoader(cfg.CertDir, logger)
	}

	publisher := metrics.NewPromPublisher(time.Now)

	scanSvc := &usecase.CertScanService{
		Loader:    loader,
		Publisher: publisher,
		Logger:    logger,
	}

	if cfg.ScanInterval > 0 {
		logger.Infof("Starting periodic scan every %s", cfg.ScanInterval)
		go scanSvc.RunPeriodic(ctx, cfg.ScanInterval)
	} else {
		scanSvc.RunOnce(ctx)
	}

	server := httpserver.NewServer(cfg.ListenAddr, logger)
	if err := server.Serve(ctx); err != nil {
		logger.Errorf("http server error: %v", err)
		os.Exit(1)
	}
}
