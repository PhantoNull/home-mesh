package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/PhantoNull/home-mesh/internal/api"
	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/discovery"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/networkscan"
	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
	"golang.org/x/crypto/ssh"
)

const (
	gracefulStreamDrainDelay = 8 * time.Second
	gracefulShutdownTimeout  = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	secretService, err := secrets.NewKeyring(cfg.MasterKeyBase, cfg.MasterKeyVersion, cfg.PreviousMasterKeys)
	if err != nil && err != secrets.ErrUnavailable {
		return err
	}

	hostKeyStore, err := sshclient.NewHostKeyStore(cfg.SSHHostKeyMode, cfg.KnownHostsPath)
	if errors.Is(err, sshclient.ErrHostKeyTrustUnavailable) {
		log.Printf("SSH disabled: %v", err)
		hostKeyStore = nil
	} else if err != nil {
		return err
	}
	var hostKeyCallback ssh.HostKeyCallback
	if hostKeyStore != nil {
		hostKeyCallback = hostKeyStore.Callback
	}

	inventory, err := store.NewWithOptions(cfg.DBPath, store.Options{SeedDemo: cfg.SeedDemoData})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := inventory.Close(); closeErr != nil {
			log.Printf("close store: %v", closeErr)
		}
	}()
	if err := api.ValidateSSHCredentials(context.Background(), inventory, secretService); err != nil {
		return err
	}

	bus := monitor.NewEventBus()
	scanCoordinator := networkscan.NewCoordinator()
	refresher := monitor.NewRefresherWithOptions(inventory, bus, monitor.RefresherOptions{
		NmapPath:    cfg.NmapPath,
		Coordinator: scanCoordinator,
	})
	discoveryService := discovery.NewServiceWithOptions(discovery.Options{
		NmapPath:            cfg.NmapPath,
		AllowPublicNetworks: cfg.DiscoveryAllowPublic,
		Coordinator:         scanCoordinator,
	})
	router, err := api.NewRouterWithHostKeyStore(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback, hostKeyStore)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTPAddr, err)
	}
	defer listener.Close()

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serviceCtx, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	backgroundCtx, cancelBackground := context.WithCancel(serviceCtx)
	server := newHTTPServer(cfg.HTTPAddr, router, serviceCtx)

	log.Printf("background refresh configured: interval=%s nmap_enabled=%t", cfg.ScanInterval, refresher.UsingNmap())
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		defer background.Done()
		refresher.RunBackground(backgroundCtx, cfg.ScanInterval)
	}()

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("home-mesh server listening on %s", listener.Addr())
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serverErrors <- err
	}()

	select {
	case err := <-serverErrors:
		router.BeginDrain()
		cancelBackground()
		cancelService()
		background.Wait()
		if drainErr := router.WaitForDrain(context.Background()); drainErr != nil {
			return fmt.Errorf("drain SSH terminals after server failure: %w", drainErr)
		}
		if err != nil {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-signalCtx.Done():
		log.Println("shutting down server...")
	}
	router.BeginDrain()
	cancelBackground()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown(shutdownCtx) }()
	terminalDrainDone := make(chan error, 1)
	go func() { terminalDrainDone <- router.WaitForDrain(context.Background()) }()

	drainTimer := time.NewTimer(gracefulStreamDrainDelay)
	shutdownChannel := (<-chan error)(shutdownDone)
	terminalDrainChannel := (<-chan error)(terminalDrainDone)
	drainTimerChannel := (<-chan time.Time)(drainTimer.C)
	shutdownDeadline := shutdownCtx.Done()
	var shutdownErr, terminalDrainErr error
	for shutdownChannel != nil || terminalDrainChannel != nil {
		select {
		case shutdownErr = <-shutdownChannel:
			shutdownChannel = nil
		case terminalDrainErr = <-terminalDrainChannel:
			terminalDrainChannel = nil
		case <-drainTimerChannel:
			// Long-lived streams and hijacked terminals observe base-context
			// cancellation after ordinary requests get an initial drain window.
			cancelService()
			drainTimerChannel = nil
		case <-shutdownDeadline:
			cancelService()
			_ = server.Close()
			shutdownDeadline = nil
		}
	}
	if drainTimerChannel != nil && !drainTimer.Stop() {
		<-drainTimer.C
	}
	cancelService()
	background.Wait()
	serveErr := <-serverErrors
	if terminalDrainErr != nil {
		return fmt.Errorf("drain SSH terminals: %w", terminalDrainErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("server shutdown: %w", shutdownErr)
	}
	if serveErr != nil {
		return fmt.Errorf("serve HTTP during shutdown: %w", serveErr)
	}

	log.Println("server stopped")
	return nil
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
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
