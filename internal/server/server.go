// Package server wires the Firego services together behind an HTTP API that
// mirrors Firebase's REST conventions (path-addressed JSON, bearer auth,
// SSE streaming) plus a small static dashboard.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"firego/internal/auth"
	"firego/internal/database"
	"firego/internal/ratelimit"
	"firego/internal/realtime"
	"firego/internal/storage"
)

const (
	// maxUploadBytes caps storage object uploads to prevent DoS.
	maxUploadBytes = 100 << 20 // 100 MiB
	// maxJSONBytes caps JSON request bodies.
	maxJSONBytes = 8 << 20 // 8 MiB
)

// validDBSegment rejects path segments that could cause confusion or inject
// control characters into the JSON tree. Dots and hyphens are allowed to
// mirror Firebase's supported key characters.
var validDBSegment = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// Server holds the application services and HTTP routing.
type Server struct {
	auth    *auth.Service
	db      *database.DB
	store   *storage.Store
	hub     *realtime.Hub
	mux     *http.ServeMux
	webRoot string
	authRL  *ratelimit.Limiter // rate limiter for auth endpoints
}

// New constructs a Server and registers all routes.
func New(a *auth.Service, db *database.DB, store *storage.Store, hub *realtime.Hub, webRoot string) *Server {
	s := &Server{
		auth:    a,
		db:      db,
		store:   store,
		hub:     hub,
		mux:     http.NewServeMux(),
		webRoot: webRoot,
		authRL:  ratelimit.New(10, time.Minute), // 10 auth requests / min / IP
	}
	s.routes()
	return s
}

// Handler returns the root HTTP handler with logging, security headers, and
// CORS applied.
func (s *Server) Handler() http.Handler {
	return logging(securityHeaders(cors(s.mux)))
}

func (s *Server) routes() {
	// Auth
	s.mux.HandleFunc("POST /v1/auth/register", s.rateLimit(s.handleRegister))
	s.mux.HandleFunc("POST /v1/auth/login", s.rateLimit(s.handleLogin))
	s.mux.HandleFunc("POST /v1/auth/logout", s.requireAuth(s.handleLogout))
	s.mux.HandleFunc("GET /v1/auth/me", s.requireAuth(s.handleMe))

	// Realtime database (REST). Trailing path is the data location.
	s.mux.HandleFunc("GET /v1/db/{path...}", s.handleDBGet)
	s.mux.HandleFunc("PUT /v1/db/{path...}", s.requireAuth(s.handleDBPut))
	s.mux.HandleFunc("PATCH /v1/db/{path...}", s.requireAuth(s.handleDBPatch))
	s.mux.HandleFunc("POST /v1/db/{path...}", s.requireAuth(s.handleDBPush))
	s.mux.HandleFunc("DELETE /v1/db/{path...}", s.requireAuth(s.handleDBDelete))

	// Realtime stream (Server-Sent Events).
	s.mux.HandleFunc("GET /v1/stream/{path...}", s.handleStream)

	// Cloud storage.
	s.mux.HandleFunc("GET /v1/storage", s.handleStorageList)
	s.mux.HandleFunc("POST /v1/storage/{name...}", s.requireAuth(s.handleStoragePut))
	s.mux.HandleFunc("GET /v1/storage/{name...}", s.handleStorageGet)
	s.mux.HandleFunc("DELETE /v1/storage/{name...}", s.requireAuth(s.handleStorageDelete))

	// Health + dashboard.
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if s.webRoot != "" {
		s.mux.Handle("/", http.FileServer(http.Dir(s.webRoot)))
	}
}

// ---------- Auth handlers ----------

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decodeJSON(w, r, &c) {
		return
	}
	user, token, err := s.auth.Register(c.Email, c.Password)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrEmailTaken) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user, "token": token})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decodeJSON(w, r, &c) {
		return
	}
	user, token, err := s.auth.Login(c.Email, c.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := s.auth.Logout(token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, user *auth.User) {
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// ---------- Database handlers ----------

func (s *Server) handleDBGet(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	val, err := s.db.Get(path)
	if errors.Is(err, database.ErrNotFound) {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) handleDBPut(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var val any
	if !decodeJSON(w, r, &val) {
		return
	}
	if err := s.db.Set(path, val); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) handleDBPatch(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var val map[string]any
	if !decodeJSON(w, r, &val) {
		return
	}
	if err := s.db.Update(path, val); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) handleDBPush(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var val any
	if !decodeJSON(w, r, &val) {
		return
	}
	key, err := s.db.Push(path, val)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": key})
}

func (s *Server) handleDBDelete(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.Delete(path); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---------- Realtime stream (SSE) ----------

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	prefix := "/" + strings.Trim(r.PathValue("path"), "/")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Override the frame-options for SSE endpoints so browser EventSource works.
	w.Header().Set("X-Accel-Buffering", "no")

	events, unsubscribe := s.hub.Subscribe(prefix)
	defer unsubscribe()

	// Send the current snapshot first so new subscribers are in sync.
	if snap, err := s.db.Get(prefix); err == nil {
		writeSSE(w, flusher, realtime.Event{Type: "put", Path: prefix, Data: snap})
	}

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			writeSSE(w, flusher, ev)
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, flusher http.Flusher, ev realtime.Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
	flusher.Flush()
}

// ---------- Storage handlers ----------

func (s *Server) handleStoragePut(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	// Limit upload size before streaming to disk.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	defer r.Body.Close()

	obj, err := s.store.Put(r.PathValue("name"), r.Header.Get("Content-Type"), r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("file too large (max %d MiB)", maxUploadBytes>>20))
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, obj)
}

func (s *Server) handleStorageGet(w http.ResponseWriter, r *http.Request) {
	obj, rc, err := s.store.Open(r.PathValue("name"))
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "object not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", obj.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleStorageDelete(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	err := s.store.Delete(r.PathValue("name"))
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "object not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleStorageList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	writeJSON(w, http.StatusOK, map[string]any{"objects": s.store.List(prefix)})
}

// ---------- Middleware & helpers ----------

type authedHandler func(http.ResponseWriter, *http.Request, *auth.User)

// requireAuth wraps a handler so it only runs for valid bearer tokens.
func (s *Server) requireAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header || token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		user, err := s.auth.Verify(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		next(w, r, user)
	}
}

// rateLimit enforces the per-IP auth rate limit.
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authRL.Allow(ratelimit.ClientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "too many requests — try again later")
			return
		}
		next(w, r)
	}
}

// securityHeaders adds defensive HTTP response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// 'unsafe-inline' required for the inline scripts/styles in the dashboard.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBytes))
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// validateDBPath rejects path segments that are empty, dot-only, or contain
// characters outside the safe Firebase key alphabet.
func validateDBPath(p string) error {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil // root path is allowed
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid path segment %q", seg)
		}
		if !validDBSegment.MatchString(seg) {
			return fmt.Errorf("path segment %q contains invalid characters", seg)
		}
	}
	return nil
}
