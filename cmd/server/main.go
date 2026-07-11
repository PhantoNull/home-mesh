package main

import (
	"context"
	"errors"
	"log"
	"net"
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
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	secretService, err := secrets.NewKeyring(cfg.MasterKeyBase, cfg.MasterKeyVersion, cfg.PreviousMasterKeys)
	if err != nil && err != secrets.ErrUnavailable {
		log.Fatal(err)
	}

	hostKeyCallback, err := sshclient.HostKeyCallback(cfg.SSHHostKeyMode, cfg.KnownHostsPath)
	if err != nil {
		log.Fatal(err)
	}

	inventory, err := store.NewWithOptions(cfg.DBPath, store.Options{SeedDemo: cfg.SeedDemoData})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := inventory.Close(); closeErr != nil {
			log.Printf("close store: %v", closeErr)
		}
	}()
	if err := api.ValidateSSHCredentials(context.Background(), inventory, secretService); err != nil {
		log.Fatal(err)
	}

	bus := monitor.NewEventBus()
	refresher := monitor.NewRefresherWithOptions(inventory, bus, monitor.RefresherOptions{NmapPath: cfg.NmapPath})
	discoveryService := discovery.NewServiceWithOptions(discovery.Options{
		NmapPath:            cfg.NmapPath,
		AllowPublicNetworks: cfg.DiscoveryAllowPublic,
	})
	router, err := api.NewRouter(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := newHTTPServer(cfg.HTTPAddr, router, ctx)

	log.Printf("background refresh configured: interval=%s nmap_enabled=%t", cfg.ScanInterval, refresher.UsingNmap())
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

func newHTTPServer(address string, handler http.Handler, baseContext context.Context) *http.Server {
	return &http.Server{
		Addr:    address,
		Handler: handler,
		BaseContext: func(net.Listener) context.Context {
			return baseContext
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Streaming handlers own their write lifecycle and detect failed flushes.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
}
