// turn-auth mints short-lived TURN credentials for Construct Meet.
//
// It implements the coturn use-auth-secret (TURN REST API) scheme: a
// credential is a time-limited HMAC over an expiry timestamp, validated by
// coturn with the SAME shared secret. The secret never leaves the server and
// never ships in the Meet bundle; leaked credentials expire within the TTL.
//
//	username   = "<unix-expiry>"            (optionally ":<user-id>" for tracing)
//	credential = base64( HMAC-SHA1( TURN_SHARED_SECRET, username ) )
//
// The gateway (my) auth-gates /api/turn/credentials and forwards identity on
// X-Auth-* headers plus X-Internal-Secret, so this service only ever sees
// authenticated callers.
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	secret         string
	realm          string
	stunURLs       []string
	turnURLs       []string
	ttl            time.Duration
	internalSecret string
	port           string
}

func load() config {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	secret := strings.TrimSpace(os.Getenv("TURN_SHARED_SECRET"))
	if secret == "" {
		log.Fatal("TURN_SHARED_SECRET is required (must match the coturn app)")
	}
	ttlSec, _ := strconv.Atoi(get("TURN_TTL_SECONDS", "86400"))
	if ttlSec <= 0 {
		ttlSec = 86400
	}
	// Comma-separated ICE URLs. stun: URLs are returned without credentials;
	// turn:/turns: URLs are grouped into one credentialed ICE server.
	urls := strings.Split(get("TURN_URLS",
		"stun:turn.lisaos.dev:3478,"+
			"turn:turn.lisaos.dev:3478?transport=udp,"+
			"turn:turn.lisaos.dev:3478?transport=tcp,"+
			"turns:turn.lisaos.dev:5349"), ",")
	var stun, turn []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		switch {
		case u == "":
		case strings.HasPrefix(u, "stun:"):
			stun = append(stun, u)
		default:
			turn = append(turn, u)
		}
	}
	return config{
		secret:         secret,
		realm:          get("TURN_REALM", "turn.lisaos.dev"),
		stunURLs:       stun,
		turnURLs:       turn,
		ttl:            time.Duration(ttlSec) * time.Second,
		internalSecret: strings.TrimSpace(os.Getenv("INTERNAL_SHARED_SECRET")),
		port:           get("PORT", "80"),
	}
}

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type credResponse struct {
	Username   string      `json:"username"`
	Credential string      `json:"credential"`
	TTL        int         `json:"ttl"`
	Realm      string      `json:"realm"`
	IceServers []iceServer `json:"iceServers"`
}

func main() {
	cfg := load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /credentials", cfg.handleCredentials)
	// Also accept the gateway-translated path in case it forwards verbatim.
	mux.HandleFunc("GET /api/credentials", cfg.handleCredentials)

	log.Printf("turn-auth listening on :%s (realm=%s ttl=%s stun=%d turn=%d)",
		cfg.port, cfg.realm, cfg.ttl, len(cfg.stunURLs), len(cfg.turnURLs))
	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func (cfg config) handleCredentials(w http.ResponseWriter, r *http.Request) {
	// Defense in depth: if the gateway shares an internal secret, require it
	// so the service can't be hit directly, only through the auth-gated edge.
	if cfg.internalSecret != "" {
		got := r.Header.Get("X-Internal-Secret")
		if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.internalSecret)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
	}

	exp := time.Now().Add(cfg.ttl).Unix()
	username := strconv.FormatInt(exp, 10)
	// Bind the credential to the authenticated user when known - purely for
	// tracing/abuse attribution; coturn HMACs the whole username string.
	if uid := strings.TrimSpace(r.Header.Get("X-Auth-User-ID")); uid != "" {
		username = username + ":" + sanitize(uid)
	}

	mac := hmac.New(sha1.New, []byte(cfg.secret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	servers := make([]iceServer, 0, 2)
	if len(cfg.stunURLs) > 0 {
		servers = append(servers, iceServer{URLs: cfg.stunURLs})
	}
	if len(cfg.turnURLs) > 0 {
		servers = append(servers, iceServer{URLs: cfg.turnURLs, Username: username, Credential: credential})
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, credResponse{
		Username:   username,
		Credential: credential,
		TTL:        int(cfg.ttl.Seconds()),
		Realm:      cfg.realm,
		IceServers: servers,
	})
}

// sanitize keeps the username free of separators that would corrupt the
// "<expiry>:<uid>" form coturn parses.
func sanitize(s string) string {
	return strings.NewReplacer(":", "_", " ", "_", "\n", "", "\r", "").Replace(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
