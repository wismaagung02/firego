// Package server wires all Firego services behind an HTTP API.
// Routes are organised in three groups:
//   - /admin/...           — app management (requires admin key)
//   - /v1/{appID}/...      — per-app client API
//   - /                    — static dashboard
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

	"firego/internal/apps"
	"firego/internal/auth"
	"firego/internal/database"
	"firego/internal/ratelimit"
	"firego/internal/realtime"
	"firego/internal/rules"
	"firego/internal/storage"
)

const (
	maxUploadBytes = 100 << 20 // 100 MiB
	maxJSONBytes   = 8 << 20  // 8 MiB
)

var validDBSegment = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// Server owns the app registry and HTTP routing.
type Server struct {
	mgr     *apps.Manager
	mux     *http.ServeMux
	webRoot string
	authRL  *ratelimit.Limiter // per-IP rate limiter for auth endpoints
	adminKey string
}

// New constructs a Server and registers all routes.
func New(mgr *apps.Manager, adminKey, webRoot string) *Server {
	s := &Server{
		mgr:      mgr,
		mux:      http.NewServeMux(),
		webRoot:  webRoot,
		authRL:   ratelimit.New(10, time.Minute),
		adminKey: adminKey,
	}
	s.routes()
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	return logging(securityHeaders(cors(s.mux)))
}

func (s *Server) routes() {
	// ── Admin API ──────────────────────────────────────────────────────
	s.mux.HandleFunc("GET /admin/apps", s.requireAdmin(s.handleListApps))
	s.mux.HandleFunc("POST /admin/apps", s.requireAdmin(s.handleCreateApp))
	s.mux.HandleFunc("GET /admin/apps/{appID}", s.requireAdmin(s.handleGetApp))
	s.mux.HandleFunc("DELETE /admin/apps/{appID}", s.requireAdmin(s.handleDeleteApp))
	s.mux.HandleFunc("GET /admin/apps/{appID}/rules", s.requireAdmin(s.handleGetRules))
	s.mux.HandleFunc("PUT /admin/apps/{appID}/rules", s.requireAdmin(s.handlePutRules))

	// ── Per-app Auth ───────────────────────────────────────────────────
	s.mux.HandleFunc("POST /v1/{appID}/auth/register", s.appRoute(s.rateLimited(s.handleRegister)))
	s.mux.HandleFunc("POST /v1/{appID}/auth/login", s.appRoute(s.rateLimited(s.handleLogin)))
	s.mux.HandleFunc("POST /v1/{appID}/auth/logout", s.appAuthRoute(s.handleLogout))
	s.mux.HandleFunc("GET /v1/{appID}/auth/me", s.appAuthRoute(s.handleMe))

	// ── Per-app Database ───────────────────────────────────────────────
	// Reads: optional auth so rules can inspect auth.uid
	s.mux.HandleFunc("GET /v1/{appID}/db/{path...}", s.appRoute(s.handleDBGet))
	// Writes: auth required; rules provide additional path-level restrictions
	s.mux.HandleFunc("PUT /v1/{appID}/db/{path...}", s.appAuthRoute(s.handleDBPut))
	s.mux.HandleFunc("PATCH /v1/{appID}/db/{path...}", s.appAuthRoute(s.handleDBPatch))
	s.mux.HandleFunc("POST /v1/{appID}/db/{path...}", s.appAuthRoute(s.handleDBPush))
	s.mux.HandleFunc("DELETE /v1/{appID}/db/{path...}", s.appAuthRoute(s.handleDBDelete))

	// ── Per-app Realtime stream (SSE) ──────────────────────────────────
	s.mux.HandleFunc("GET /v1/{appID}/stream/{path...}", s.appRoute(s.handleStream))

	// ── Per-app Storage ────────────────────────────────────────────────
	s.mux.HandleFunc("GET /v1/{appID}/storage", s.appRoute(s.handleStorageList))
	s.mux.HandleFunc("POST /v1/{appID}/storage/{name...}", s.appAuthRoute(s.handleStoragePut))
	s.mux.HandleFunc("GET /v1/{appID}/storage/{name...}", s.appRoute(s.handleStorageGet))
	s.mux.HandleFunc("DELETE /v1/{appID}/storage/{name...}", s.appAuthRoute(s.handleStorageDelete))

	// ── Misc ───────────────────────────────────────────────────────────
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if s.webRoot != "" {
		s.mux.Handle("/", http.FileServer(http.Dir(s.webRoot)))
	}
}

// ─── Handler type aliases ───────────────────────────────────────────────────

// appHandler receives the resolved App.
type appHandler func(http.ResponseWriter, *http.Request, *apps.App)

// appAuthedHandler receives the resolved App and the authenticated user.
type appAuthedHandler func(http.ResponseWriter, *http.Request, *apps.App, *auth.User)

// appRoute resolves the {appID} wildcard and calls next.
func (s *Server) appRoute(next appHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, ok := s.resolveApp(w, r)
		if !ok {
			return
		}
		next(w, r, app)
	}
}

// appAuthRoute resolves app and verifies the bearer token, then calls next.
func (s *Server) appAuthRoute(next appAuthedHandler) http.HandlerFunc {
	return s.appRoute(func(w http.ResponseWriter, r *http.Request, app *apps.App) {
		user, ok := s.extractAuth(w, r, app, true)
		if !ok {
			return
		}
		next(w, r, app, user)
	})
}

// rateLimited wraps an appHandler with the auth rate limiter.
func (s *Server) rateLimited(next appHandler) appHandler {
	return func(w http.ResponseWriter, r *http.Request, app *apps.App) {
		if !s.authRL.Allow(ratelimit.ClientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "too many requests — try again later")
			return
		}
		next(w, r, app)
	}
}

// resolveApp looks up the app named in the {appID} path variable.
func (s *Server) resolveApp(w http.ResponseWriter, r *http.Request) (*apps.App, bool) {
	id := r.PathValue("appID")
	app, err := s.mgr.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown app: "+id)
		return nil, false
	}
	return app, true
}

// extractAuth reads the bearer token and verifies it against app.Auth.
// If require is true, missing/invalid tokens produce a 401 response.
// If require is false, a missing token returns (nil, true) so rules can
// evaluate with unauthenticated context.
func (s *Server) extractAuth(w http.ResponseWriter, r *http.Request, app *apps.App, require bool) (*auth.User, bool) {
	header := r.Header.Get("Authorization")
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header || token == "" {
		if require {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return nil, false
		}
		return nil, true
	}
	user, err := app.Auth.Verify(token)
	if err != nil {
		if require {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return nil, false
		}
		return nil, true // treat bad token as unauthenticated for rule eval
	}
	return user, true
}

// authCtx builds a rules.AuthCtx from an optional *auth.User.
func authCtx(user *auth.User) rules.AuthCtx {
	if user == nil {
		return rules.AuthCtx{}
	}
	return rules.AuthCtx{UID: user.UID, Email: user.Email, Authed: true}
}

// ─── Admin handlers ─────────────────────────────────────────────────────────

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if key == "" {
			key = r.Header.Get("X-Admin-Key")
		}
		if key != s.adminKey {
			writeError(w, http.StatusUnauthorized, "invalid admin key")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apps": s.mgr.List()})
}

func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	app, err := s.mgr.Create(body.ID, body.Name)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, apps.ErrIDTaken) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, app.Info)
}

func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.mgr.Get(r.PathValue("appID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, app.Info)
}

func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Delete(r.PathValue("appID")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, apps.ErrNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, apps.ErrProtected) {
			status = http.StatusForbidden
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	app, err := s.mgr.Get(r.PathValue("appID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	data, err := app.Rules.RawJSON()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	app, err := s.mgr.Get(r.PathValue("appID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBytes))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := app.Rules.Update(data); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rules JSON: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

// ─── Auth handlers ───────────────────────────────────────────────────────────

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, app *apps.App) {
	var c struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &c) {
		return
	}
	user, token, err := app.Auth.Register(c.Email, c.Password)
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, app *apps.App) {
	var c struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &c) {
		return
	}
	user, token, err := app.Auth.Login(c.Email, c.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, app *apps.App, _ *auth.User) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := app.Auth.Logout(token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, _ *apps.App, user *auth.User) {
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// ─── Database handlers ───────────────────────────────────────────────────────

func (s *Server) handleDBGet(w http.ResponseWriter, r *http.Request, app *apps.App) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Optional auth so rules can evaluate auth.uid.
	user, _ := s.extractAuth(w, r, app, false)
	if !app.Rules.CanRead(path, authCtx(user)) {
		writeError(w, http.StatusForbidden, "read denied by security rules")
		return
	}
	val, err := app.DB.Get(path)
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

func (s *Server) handleDBPut(w http.ResponseWriter, r *http.Request, app *apps.App, user *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !app.Rules.CanWrite(path, authCtx(user)) {
		writeError(w, http.StatusForbidden, "write denied by security rules")
		return
	}
	var val any
	if !decodeJSON(w, r, &val) {
		return
	}
	if err := app.DB.Set(path, val); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) handleDBPatch(w http.ResponseWriter, r *http.Request, app *apps.App, user *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !app.Rules.CanWrite(path, authCtx(user)) {
		writeError(w, http.StatusForbidden, "write denied by security rules")
		return
	}
	var val map[string]any
	if !decodeJSON(w, r, &val) {
		return
	}
	if err := app.DB.Update(path, val); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) handleDBPush(w http.ResponseWriter, r *http.Request, app *apps.App, user *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !app.Rules.CanWrite(path, authCtx(user)) {
		writeError(w, http.StatusForbidden, "write denied by security rules")
		return
	}
	var val any
	if !decodeJSON(w, r, &val) {
		return
	}
	key, err := app.DB.Push(path, val)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": key})
}

func (s *Server) handleDBDelete(w http.ResponseWriter, r *http.Request, app *apps.App, user *auth.User) {
	path := r.PathValue("path")
	if err := validateDBPath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !app.Rules.CanWrite(path, authCtx(user)) {
		writeError(w, http.StatusForbidden, "write denied by security rules")
		return
	}
	if err := app.DB.Delete(path); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ─── Realtime stream (SSE) ───────────────────────────────────────────────────

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, app *apps.App) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	prefix := "/" + strings.Trim(r.PathValue("path"), "/")
	user, _ := s.extractAuth(w, r, app, false)

	if !app.Rules.CanRead(prefix, authCtx(user)) {
		writeError(w, http.StatusForbidden, "read denied by security rules")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	events, unsubscribe := app.Hub.Subscribe(prefix)
	defer unsubscribe()

	if snap, err := app.DB.Get(prefix); err == nil {
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

// ─── Storage handlers ────────────────────────────────────────────────────────

func (s *Server) handleStoragePut(w http.ResponseWriter, r *http.Request, app *apps.App, _ *auth.User) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	defer r.Body.Close()
	obj, err := app.Store.Put(r.PathValue("name"), r.Header.Get("Content-Type"), r.Body)
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

func (s *Server) handleStorageGet(w http.ResponseWriter, r *http.Request, app *apps.App) {
	obj, rc, err := app.Store.Open(r.PathValue("name"))
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

func (s *Server) handleStorageDelete(w http.ResponseWriter, r *http.Request, app *apps.App, _ *auth.User) {
	if err := app.Store.Delete(r.PathValue("name")); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleStorageList(w http.ResponseWriter, r *http.Request, app *apps.App) {
	writeJSON(w, http.StatusOK, map[string]any{"objects": app.Store.List(r.URL.Query().Get("prefix"))})
}

// ─── Middleware ──────────────────────────────────────────────────────────────

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Admin-Key")
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, maxJSONBytes)).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
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

func validateDBPath(p string) error {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
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
