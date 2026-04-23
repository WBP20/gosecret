package server

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"gosecret/internal/store"
)

type Config struct {
	BaseURL            string
	MaxCiphertextBytes int
	MaxQuestionBytes   int
	MaxAnswerBytes     int
	DefaultTTL         time.Duration
	MaxTTL             time.Duration
	DefaultMaxAttempts int
	MaxActiveSecrets   int
	TrustProxy         bool
}

func DefaultConfig() Config {
	return Config{
		MaxCiphertextBytes: 64 * 1024,
		MaxQuestionBytes:   512,
		MaxAnswerBytes:     1024,
		DefaultTTL:         24 * time.Hour,
		MaxTTL:             7 * 24 * time.Hour,
		DefaultMaxAttempts: 5,
		MaxActiveSecrets:   10000,
	}
}

type Server struct {
	cfg          Config
	store        *store.Store
	serverSecret []byte
	web          fs.FS
	createLim    *ipLimiter
	unlockLim    *ipLimiter
}

func New(cfg Config, st *store.Store, serverSecret []byte, web fs.FS) *Server {
	return &Server{
		cfg:          cfg,
		store:        st,
		serverSecret: serverSecret,
		web:          web,
		createLim:    newIPLimiter(1, 10),
		unlockLim:    newIPLimiter(0.2, 5),
	}
}

// Routes returns an http.Handler with all routes mounted.
func (s *Server) Routes(staticFS embed.FS) http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(staticFS, "web")
	if err != nil {
		log.Fatalf("embedded fs: %v", err)
	}

	mux.HandleFunc("GET /{$}", s.serveFile(sub, "create.html"))
	mux.HandleFunc("GET /s/{id}", s.serveFile(sub, "view.html"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", noDirListing(http.FileServer(http.FS(sub)))))

	mux.HandleFunc("POST /api/secrets", s.handleCreate)
	mux.HandleFunc("GET /api/secrets/{id}", s.handleMeta)
	mux.HandleFunc("POST /api/secrets/{id}/unlock", s.handleUnlock)
	mux.HandleFunc("POST /api/secrets/{id}/consume", s.handleConsume)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return securityHeaders(mux)
}

func (s *Server) serveFile(fsys fs.FS, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.Split(fwd, ",")
			// Rightmost entry is the one added by our reverse proxy.
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func requireJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/json")
}

func isValidID(id string) bool {
	if len(id) < 16 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

type createReq struct {
	Ciphertext  string `json:"ciphertext"`  // base64
	IV          string `json:"iv"`          // base64
	Question    string `json:"question"`    // optional
	Answer      string `json:"answer"`      // optional (cleartext, normalized+HMACed server-side)
	TTLSeconds  int    `json:"ttl_seconds"` // optional
	MaxAttempts int    `json:"max_attempts"`
}

type createResp struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !s.createLim.Allow(clientIP(r, s.cfg.TrustProxy)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	if !requireJSON(r) {
		writeErr(w, http.StatusUnsupportedMediaType, "bad_content_type", "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.MaxCiphertextBytes)*2)
	var req createReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_json", "invalid JSON body")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil || len(ct) == 0 || len(ct) > s.cfg.MaxCiphertextBytes {
		writeErr(w, http.StatusBadRequest, "bad_ciphertext", "invalid or too large ciphertext")
		return
	}
	iv, err := base64.StdEncoding.DecodeString(req.IV)
	if err != nil || len(iv) == 0 || len(iv) > 32 {
		writeErr(w, http.StatusBadRequest, "bad_iv", "invalid iv")
		return
	}
	if len(req.Question) > s.cfg.MaxQuestionBytes {
		writeErr(w, http.StatusBadRequest, "bad_question", "question too long")
		return
	}
	if len(req.Answer) > s.cfg.MaxAnswerBytes {
		writeErr(w, http.StatusBadRequest, "bad_answer", "answer too long")
		return
	}
	if (req.Question == "") != (req.Answer == "") {
		writeErr(w, http.StatusBadRequest, "bad_qa", "question and answer must both be set or both empty")
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = s.cfg.DefaultTTL
	}
	if ttl > s.cfg.MaxTTL {
		ttl = s.cfg.MaxTTL
	}
	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = s.cfg.DefaultMaxAttempts
	}
	if maxAttempts > 20 {
		maxAttempts = 20
	}

	id, err := RandomID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rand", "failed")
		return
	}

	sec := &store.Secret{
		ID:          id,
		Ciphertext:  ct,
		IV:          iv,
		Question:    strings.TrimSpace(req.Question),
		MaxAttempts: maxAttempts,
		ExpiresAt:   time.Now().Add(ttl),
		CreatedAt:   time.Now(),
	}
	if req.Answer != "" {
		sec.AnswerHash = AnswerHash(s.serverSecret, id, req.Answer)
	}
	if err := s.store.PutIfUnder(sec, s.cfg.MaxActiveSecrets); err != nil {
		if errors.Is(err, store.ErrCapacity) {
			writeErr(w, http.StatusServiceUnavailable, "capacity", "server at capacity, try again later")
		} else {
			writeErr(w, http.StatusInternalServerError, "store", "failed to store secret")
		}
		return
	}
	url := s.cfg.BaseURL + "/s/" + id
	log.Printf("secret created id=%s ttl=%s challenge=%t ip=%s",
		id, ttl, req.Answer != "", clientIP(r, s.cfg.TrustProxy))
	writeJSON(w, http.StatusCreated, createResp{ID: id, URL: url, ExpiresAt: sec.ExpiresAt})
}

type metaResp struct {
	ID          string    `json:"id"`
	HasQuestion bool      `json:"has_question"`
	Question    string    `json:"question,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	Consumed    bool      `json:"consumed"`
	Expired     bool      `json:"expired"`
	Locked      bool      `json:"locked"`
	Remaining   int       `json:"remaining_attempts"`
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if !s.unlockLim.Allow(clientIP(r, s.cfg.TrustProxy)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	id := r.PathValue("id")
	if !isValidID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	sec, err := s.store.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	if sec.ConsumedAt != nil || time.Now().After(sec.ExpiresAt) ||
		(sec.MaxAttempts > 0 && sec.Attempts >= sec.MaxAttempts) {
		writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	resp := metaResp{
		ID:          sec.ID,
		HasQuestion: sec.AnswerHash != nil,
		Question:    sec.Question,
		ExpiresAt:   sec.ExpiresAt,
		Consumed:    false,
		Expired:     false,
		Locked:      false,
		Remaining:   max0(sec.MaxAttempts - sec.Attempts),
	}
	writeJSON(w, http.StatusOK, resp)
}

type unlockReq struct {
	Answer string `json:"answer"`
}

type payloadResp struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.unlockLim.Allow(clientIP(r, s.cfg.TrustProxy)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, slow down")
		return
	}
	if !requireJSON(r) {
		writeErr(w, http.StatusUnsupportedMediaType, "bad_content_type", "Content-Type must be application/json")
		return
	}
	id := r.PathValue("id")
	if !isValidID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var req unlockReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_json", "invalid JSON body")
		return
	}
	if len(req.Answer) > 1024 {
		writeErr(w, http.StatusBadRequest, "bad_answer", "answer too long")
		return
	}

	var delivered *store.Secret
	sec, err := s.store.Update(id, func(sec *store.Secret) error {
		if time.Now().After(sec.ExpiresAt) {
			return store.ErrExpired
		}
		if sec.ConsumedAt != nil {
			return store.ErrConsumed
		}
		if sec.AnswerHash == nil {
			return errors.New("no_question")
		}
		if sec.MaxAttempts > 0 && sec.Attempts >= sec.MaxAttempts {
			return store.ErrLocked
		}
		expected := AnswerHash(s.serverSecret, id, req.Answer)
		if !HashEqual(sec.AnswerHash, expected) {
			sec.Attempts++
			return errBadAnswer
		}
		now := time.Now()
		sec.UnlockedAt = &now
		sec.ConsumedAt = &now
		delivered = &store.Secret{Ciphertext: sec.Ciphertext, IV: sec.IV}
		sec.Ciphertext = nil
		sec.IV = nil
		sec.AnswerHash = nil
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		case errors.Is(err, store.ErrExpired):
			writeErr(w, http.StatusGone, "expired", "secret expired")
		case errors.Is(err, store.ErrConsumed):
			writeErr(w, http.StatusGone, "consumed", "secret already consumed")
		case errors.Is(err, store.ErrLocked):
			log.Printf("unlock locked id=%s ip=%s", id, clientIP(r, s.cfg.TrustProxy))
			writeErr(w, http.StatusLocked, "locked", "too many failed attempts")
		case errors.Is(err, errBadAnswer):
			remaining := 0
			if sec != nil {
				remaining = max0(sec.MaxAttempts - sec.Attempts)
			}
			log.Printf("unlock failed id=%s remaining=%d ip=%s",
				id, remaining, clientIP(r, s.cfg.TrustProxy))
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":              "bad_answer",
				"message":            "incorrect answer",
				"remaining_attempts": remaining,
			})
		default:
			writeErr(w, http.StatusBadRequest, "invalid", "invalid request")
		}
		return
	}
	writeJSON(w, http.StatusOK, payloadResp{
		Ciphertext: base64.StdEncoding.EncodeToString(delivered.Ciphertext),
		IV:         base64.StdEncoding.EncodeToString(delivered.IV),
	})
}

var errBadAnswer = errors.New("bad_answer")

func (s *Server) handleConsume(w http.ResponseWriter, r *http.Request) {
	if !s.unlockLim.Allow(clientIP(r, s.cfg.TrustProxy)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	if !requireJSON(r) {
		writeErr(w, http.StatusUnsupportedMediaType, "bad_content_type", "Content-Type must be application/json")
		return
	}
	id := r.PathValue("id")
	if !isValidID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var delivered *store.Secret
	_, err := s.store.Update(id, func(sec *store.Secret) error {
		if time.Now().After(sec.ExpiresAt) {
			return store.ErrExpired
		}
		if sec.ConsumedAt != nil {
			return store.ErrConsumed
		}
		if sec.AnswerHash != nil {
			return errors.New("question_required")
		}
		now := time.Now()
		sec.ConsumedAt = &now
		delivered = &store.Secret{Ciphertext: sec.Ciphertext, IV: sec.IV}
		sec.Ciphertext = nil
		sec.IV = nil
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not_found", "secret not found")
		case errors.Is(err, store.ErrExpired):
			writeErr(w, http.StatusGone, "expired", "secret expired")
		case errors.Is(err, store.ErrConsumed):
			writeErr(w, http.StatusGone, "consumed", "secret already consumed")
		default:
			writeErr(w, http.StatusBadRequest, "invalid", "invalid request")
		}
		return
	}
	writeJSON(w, http.StatusOK, payloadResp{
		Ciphertext: base64.StdEncoding.EncodeToString(delivered.Ciphertext),
		IV:         base64.StdEncoding.EncodeToString(delivered.IV),
	})
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// StartPurger runs a background goroutine that purges expired secrets.
func (s *Server) StartPurger(interval, grace time.Duration, stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if n, err := s.store.PurgeExpired(grace); err == nil && n > 0 {
					log.Printf("purger: removed %d expired secrets", n)
				}
				s.createLim.sweep(time.Hour)
				s.unlockLim.sweep(time.Hour)
			case <-stop:
				return
			}
		}
	}()
}

func noDirListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "browsing-topics=(), interest-cohort=()")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		// Strict CSP: only inline styles allowed (we keep all JS in external files).
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
				"font-src 'self'; img-src 'self' data:; connect-src 'self'; "+
				"base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}
