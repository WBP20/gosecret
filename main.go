package main

import (
	"context"
	"embed"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gosecret/internal/server"
	"gosecret/internal/store"
)

//go:embed web/*
var webFS embed.FS

func main() {
	var (
		addr       = flag.String("addr", ":8080", "listen address")
		dataDir    = flag.String("data", "./data", "data directory for bbolt db + server key")
		baseURL    = flag.String("base-url", "", "public base URL (e.g. https://gosecret.example.com); defaults to http://<addr>")
		trustProxy = flag.Bool("trust-proxy", false, "trust X-Forwarded-For header (only enable behind a reverse proxy)")
	)
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}

	st, err := store.Open(filepath.Join(*dataDir, "gosecret.db"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	secret, err := server.LoadOrCreateServerSecret(filepath.Join(*dataDir, "server.key"))
	if err != nil {
		log.Fatalf("server secret: %v", err)
	}

	cfg := server.DefaultConfig()
	cfg.TrustProxy = *trustProxy
	if *baseURL == "" {
		cfg.BaseURL = "http://localhost" + *addr
	} else {
		cfg.BaseURL = *baseURL
	}

	s := server.New(cfg, st, secret, webFS)

	stop := make(chan struct{})
	s.StartPurger(5*time.Minute, 1*time.Minute, stop)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           s.Routes(webFS),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("GoSecret listening on %s (base=%s)", *addr, cfg.BaseURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
