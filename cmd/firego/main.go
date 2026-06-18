// Command firego starts the Firego server — a Firebase-like backend offering
// multi-app support, authentication, realtime JSON database with security rules,
// and cloud storage.
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

	"firego/internal/apps"
	"firego/internal/server"
)

func main() {
	addr    := flag.String("addr", envOr("FIREGO_ADDR", ":8080"), "HTTP listen address")
	dataDir := flag.String("data", envOr("FIREGO_DATA", "data"),  "directory for persisted data")
	webDir  := flag.String("web",  envOr("FIREGO_WEB",  "web"),   "directory served as the dashboard")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	masterSecret := loadOrGenKey(filepath.Join(*dataDir, "secret.key"))
	adminKey     := loadOrGenKey(filepath.Join(*dataDir, "admin.key"))

	mgr, err := apps.New(*dataDir, masterSecret)
	if err != nil {
		log.Fatalf("init app manager: %v", err)
	}

	log.Printf("Admin key: %s", adminKey)

	srv := server.New(mgr, string(adminKey), *webDir)
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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// loadOrGenKey reads an existing key from path or creates and persists a fresh one.
func loadOrGenKey(path string) []byte {
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		return data
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("generate key: %v", err)
	}
	encoded := []byte(hex.EncodeToString(b))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		log.Fatalf("persist key %s: %v", path, err)
	}
	return encoded
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
