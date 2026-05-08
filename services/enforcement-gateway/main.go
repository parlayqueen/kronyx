package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"kronyx/pkg/canonicaljson"
	"kronyx/pkg/replay"
	"kronyx/pkg/tokens"
)

type keyring struct {
	keys map[string]ed25519.PublicKey
}

type revocationCache struct {
	mu          sync.RWMutex
	entries     map[string]time.Time
	lastRefresh time.Time
}

func main() {
	kr, err := loadKeyring(os.Getenv("KRONYX_PUBLIC_KEYS"))
	if err != nil {
		log.Fatalf("failed to load keyring: %v", err)
	}
	replays := replay.NewRegistry()
	revocations := &revocationCache{entries: map[string]time.Time{}}

	tokenServiceURL := os.Getenv("TOKEN_SERVICE_URL")
	requireRevocationFeed := os.Getenv("REQUIRE_REVOCATION_FEED") == "true"
	revocationMaxStaleness := parseLeeway(os.Getenv("REVOCATION_MAX_STALENESS_SECONDS"), 30)
	if tokenServiceURL != "" {
		if err := revocations.refresh(tokenServiceURL); err != nil {
			log.Printf("initial revocation refresh failed: %v", err)
		}
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for range t.C {
				if err := revocations.refresh(tokenServiceURL); err != nil {
					log.Printf("revocation refresh failed: %v", err)
				}
			}
		}()
	}

	leeway := parseLeeway(os.Getenv("TOKEN_CLOCK_SKEW_SECONDS"), 30)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"revocation_entries": revocations.size(),
			"last_refresh":       revocations.lastRefreshTime().Format(time.RFC3339Nano),
		})
	})
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if requireRevocationFeed && tokenServiceURL != "" && revocations.staleFor() > revocationMaxStaleness {
			http.Error(w, "revocation feed stale; fail-closed", http.StatusServiceUnavailable)
			return
		}
		raw, err := bearer(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		tok, err := tokens.Parse(raw)
		if err != nil {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		pub, ok := kr.keys[tok.Claims.KeyID]
		if !ok {
			http.Error(w, "unknown key id", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		if err := tokens.Verify(pub, tok, "enforcement-gateway", now.Add(-leeway)); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if nonce := r.Header.Get("X-Kronyx-Nonce"); nonce == "" || nonce != tok.Claims.Nonce {
			http.Error(w, "nonce mismatch", http.StatusUnauthorized)
			return
		}
		if revocations.contains(tok.Claims.Revocation) {
			http.Error(w, "token lineage revoked", http.StatusForbidden)
			return
		}
		if !replays.MarkUsed(tok.Claims.TokenID, time.Until(tok.Claims.ExpiresAt)+time.Minute) {
			http.Error(w, "token replay detected", http.StatusConflict)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		canon, err := canonicaljson.Marshal(body)
		if err != nil {
			http.Error(w, "canonicalization failed", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "token_id": tok.Claims.TokenID, "request_canonical": string(canon)})
	})
	log.Fatal(http.ListenAndServe(":8083", mux))
}

func bearer(r *http.Request) (string, error) {
	a := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(a) <= len(p) || a[:len(p)] != p {
		return "", errors.New("missing bearer token")
	}
	return a[len(p):], nil
}

func loadKeyring(raw string) (keyring, error) {
	if raw == "" {
		return keyring{}, errors.New("KRONYX_PUBLIC_KEYS must be set")
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return keyring{}, err
	}
	out := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize || k.Kid == "" {
			continue
		}
		out[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return keyring{}, errors.New("no valid keys loaded")
	}
	return keyring{keys: out}, nil
}

func parseLeeway(raw string, def int) time.Duration {
	if raw == "" {
		return time.Duration(def) * time.Second
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 || v > 300 {
		return time.Duration(def) * time.Second
	}
	return time.Duration(v) * time.Second
}

func (r *revocationCache) refresh(baseURL string) error {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/v1/revocations")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("non-200 revocation response")
	}
	data := map[string]time.Time{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = data
	r.lastRefresh = time.Now().UTC()
	return nil
}

func (r *revocationCache) contains(ref string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[ref]
	return ok
}

func (r *revocationCache) staleFor() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastRefresh.IsZero() {
		return 365 * 24 * time.Hour
	}
	return time.Since(r.lastRefresh)
}

func (r *revocationCache) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

func (r *revocationCache) lastRefreshTime() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRefresh
}
