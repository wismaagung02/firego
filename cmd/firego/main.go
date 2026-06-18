// Command firego starts the Firego server: a small, dependency-free
// Firebase-style backend offering authentication, a realtime JSON database
// and cloud storage over HTTP.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"firego/internal/auth"
	"firego/internal/database"
	"firego/internal/realtime"
	"firego/internal/server"
	"firego/internal/storage"
)

func main() {
	addr := flag.String("addr", envOr("FIREGO_ADDR", ":8080"), "HTTP listen address")
	dataDir := flag.String("data", envOr("FIREGO_DATA", "data"), "directory for persisted data")
	webDir := flag.String("web", envOr("FIREGO_WEB", "web"), "directory served as the dashboard")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	secret := loadSecret(filepath.Join(*dataDir, "secret.key"))

	hub := realtime.NewHub()

	authSvc, err := auth.New(filepath.Join(*dataDir, "users.json"), secret)
	if err != nil {
		log.Fatalf("init auth: %v", err)
	}
	db, err := database.New(filepath.Join(*dataDir, "database.json"), hub)
	if err != nil {
		log.Fatalf("init database: %v", err)
	}
	store, err := storage.New(filepath.Join(*dataDir, "storage"))
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}

	srv := server.New(authSvc, db, store, hub, *webDir)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Firego listening on %s (data=%s)", *addr, *dataDir)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

// loadSecret reads the JWT signing secret from path, generating and persisting
// a new random one on first run.
func loadSecret(path string) []byte {
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		return data
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("generate secret: %v", err)
	}
	encoded := []byte(hex.EncodeToString(secret))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		log.Fatalf("persist secret: %v", err)
	}
	return encoded
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
