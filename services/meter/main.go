package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"kronyx/pkg/policy"
)

func main() {
	bundle, err := loadBundle(os.Getenv("METER_POLICY_PATH"))
	if err != nil {
		log.Fatalf("failed to load policy bundle: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
