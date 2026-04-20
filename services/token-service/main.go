package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"kronyx/pkg/crypto"
	"kronyx/pkg/ids"
	"kronyx/pkg/tokens"
)

type keyset struct {
	mu             sync.RWMutex
	active         string
	private        map[string]ed25519.PrivateKey
	public         map[string]ed25519.PublicKey
	revoked        map[string]time.Time
	revocationFile string
}

func main() {
	ks := newKeyset(os.Getenv("TOKEN_REVOCATION_FILE"))
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for range t.C {
			ks.gcRevocations(30 * 24 * time.Hour)
			_ = ks.persistRevocations()
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			MeterResult string            `json:"meter_result"`
			ActionType  string            `json:"action_type"`
			Subject     string            `json:"subject"`
			Resource    string            `json:"resource"`
			Bounds      map[string]string `json:"bounds"`
			Audience    string            `json:"audience"`
			TTLSeconds  int               `json:"ttl_seconds"`
			MaxTTL      string            `json:"max_ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.MeterResult != "allow" {
			http.Error(w, "meter denied", http.StatusForbidden)
			return
		}
		ttl := time.Duration(in.TTLSeconds) * time.Second
		if in.MaxTTL != "" {
			if c, err := strconv.Atoi(in.MaxTTL); err == nil && ttl > time.Duration(c)*time.Second {
				ttl = time.Duration(c) * time.Second
			}
		}
		if ttl <= 0 || ttl > 10*time.Minute {
			http.Error(w, "invalid ttl", http.StatusBadRequest)
			return
		}
		kid, priv := ks.activeKey()
		claims := tokens.Claims{TokenID: ids.New(), ActionType: in.ActionType, Subject: in.Subject, Resource: in.Resource, Bounds: in.Bounds, Audience: in.Audience, ExpiresAt: time.Now().UTC().Add(ttl), Nonce: ids.New(), Revocation: ids.New(), IssuedAt: time.Now().UTC(), KeyID: kid}
		raw, err := tokens.Mint(priv, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": raw, "claims": claims})
	})
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(ks.publicJWK())
			return
		}
		if r.Method == http.MethodPost {
			kid, err := ks.rotateActiveKey()
			if err != nil {
				http.Error(w, "failed to rotate key", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"active_kid": kid})
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/v1/revocations", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ks.revocationSnapshot())
	})
	mux.HandleFunc("/v1/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			RevocationRef string `json:"revocation_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RevocationRef == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := ks.revoke(in.RevocationRef); err != nil {
			http.Error(w, "failed to persist revocation", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	addr := os.Getenv("TOKEN_ADDR")
	if addr == "" {
		addr = ":8082"
	}
	log.Printf("token service listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newKeyset(revocationFile string) *keyset {
	kp, err := crypto.NewKeyPair()
	if err != nil {
		panic(err)
	}
	kid := "k-" + ids.New()
	ks := &keyset{active: kid, private: map[string]ed25519.PrivateKey{kid: kp.Private}, public: map[string]ed25519.PublicKey{kid: kp.Public}, revoked: map[string]time.Time{}, revocationFile: revocationFile}
	_ = ks.loadRevocations()
	return ks
}

func (k *keyset) activeKey() (string, ed25519.PrivateKey) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active, k.private[k.active]
}

func (k *keyset) publicJWK() map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	keys := make([]map[string]string, 0, len(k.public))
	for kid, key := range k.public {
		keys = append(keys, map[string]string{"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	return map[string]any{"keys": keys}
}

func (k *keyset) revoke(ref string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.revoked[ref] = time.Now().UTC()
	return k.persistRevocations()
}

func (k *keyset) revocationSnapshot() map[string]time.Time {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]time.Time, len(k.revoked))
	for key, value := range k.revoked {
		out[key] = value
	}
	return out
}

func (k *keyset) loadRevocations() error {
	if k.revocationFile == "" {
		return nil
	}
	b, err := os.ReadFile(k.revocationFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var rev map[string]time.Time
	if err := json.Unmarshal(b, &rev); err != nil {
		return err
	}
	k.revoked = rev
	return nil
}

func (k *keyset) persistRevocations() error {
	if k.revocationFile == "" {
		return nil
	}
	b, err := json.Marshal(k.revoked)
	if err != nil {
		return err
	}
	return os.WriteFile(k.revocationFile, b, 0o600)
}

func (k *keyset) rotateActiveKey() (string, error) {
	kp, err := crypto.NewKeyPair()
	if err != nil {
		return "", err
	}
	kid := "k-" + ids.New()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.private[kid] = kp.Private
	k.public[kid] = kp.Public
	k.active = kid
	return kid, nil
}

func (k *keyset) gcRevocations(ttl time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cutoff := time.Now().UTC().Add(-ttl)
	for ref, ts := range k.revoked {
		if ts.Before(cutoff) {
			delete(k.revoked, ref)
		}
	}
}
