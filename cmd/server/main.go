package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/PhantoNull/home-mesh/internal/api"
	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/discovery"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
)

func main() {
	cfg := config.Load()
	inventory, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := inventory.Close(); closeErr != nil {
			log.Printf("close store: %v", closeErr)
		}
	}()

	bus := monitor.NewEventBus()
	refresher := monitor.NewRefresher(inventory, bus)
	discoveryService := discovery.NewService(cfg.NmapPath)
	secretService, err := secrets.New(cfg.MasterKeyBase)
	if err != nil && err != secrets.ErrUnavailable {
		log.Fatal(err)
	}

	hostKeyCallback, err := sshclient.HostKeyCallback(cfg.SSHHostKeyMode, cfg.KnownHostsPath)
	if err != nil {
		log.Fatal(err)
	}

	router, err := api.NewRouter(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go refresher.RunBackground(ctx, cfg.ScanInterval)

	go func() {
		log.Printf("home-mesh server listening on %s", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}

	log.Println("server stopped")
}
