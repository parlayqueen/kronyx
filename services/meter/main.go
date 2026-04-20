package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"

	"kronyx/pkg/policy"
)

type bundleStore struct {
	mu     sync.RWMutex
	bundle policy.Bundle
	path   string
}

func main() {
	path := os.Getenv("METER_POLICY_PATH")
	bundle, err := loadBundle(path)
	if err != nil {
		log.Fatalf("failed to load policy bundle: %v", err)
	}
	store := &bundleStore{bundle: bundle, path: path}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(store.get())
			return
		}
		if r.Method == http.MethodPost {
			if err := store.reload(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "reloaded", "version": store.get().Version})
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req policy.ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		bundle := store.get()
		res, err := policy.Evaluate(bundle, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"policy_version": bundle.Version, "result": res})
	})
	addr := os.Getenv("METER_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	log.Printf("meter listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *bundleStore) get() policy.Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle
}

func (s *bundleStore) reload() error {
	if s.path == "" {
		return errors.New("reload requires METER_POLICY_PATH")
	}
	b, err := loadBundle(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.bundle = b
	s.mu.Unlock()
	return nil
}

func loadBundle(path string) (policy.Bundle, error) {
	if path == "" {
		return policy.Bundle{Version: "2026.03.25", Rules: []policy.Rule{{ID: "prod-deploy-sre", ActionType: "deploy.promote_to_prod", Env: "prod", AllowedGroups: []string{"sre"}, ResourcePrefix: "service/", RequiredAttrs: map[string]string{"mfa": "true"}, MaxTTLSeconds: 300, RequiredPhase: "change_window_open"}}}, nil
	}
	f, err := os.ReadFile(path)
	if err != nil {
		return policy.Bundle{}, err
	}
	var b policy.Bundle
	if err := json.Unmarshal(f, &b); err != nil {
		return policy.Bundle{}, err
	}
	if b.Version == "" || len(b.Rules) == 0 {
		return policy.Bundle{}, errors.New("invalid policy bundle")
	}
	return b, nil
}
