package main

import (
	"log"
	"net/http"
	"time"

	"github.com/PhantoNull/home-mesh/internal/api"
	"github.com/PhantoNull/home-mesh/internal/config"
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

	refresher := monitor.NewRefresher(inventory)
	secretService, err := secrets.New(cfg.MasterKeyBase)
	if err != nil && err != secrets.ErrUnavailable {
		log.Fatal(err)
	}

	hostKeyCallback, err := sshclient.HostKeyCallback(cfg.SSHHostKeyMode, cfg.KnownHostsPath)
	if err != nil {
		log.Fatal(err)
	}

	router, err := api.NewRouter(cfg, inventory, refresher, secretService, hostKeyCallback)
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

	log.Printf("home-mesh server listening on %s", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
