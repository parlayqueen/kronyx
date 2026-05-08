package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseLeewayBounds(t *testing.T) {
	if got := parseLeeway("120", 30); got != 120*time.Second {
		t.Fatalf("unexpected leeway: %v", got)
	}
	if got := parseLeeway("999", 30); got != 30*time.Second {
		t.Fatalf("expected default for invalid high leeway, got %v", got)
	}
}

func TestRevocationCacheRefresh(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]time.Time{"rev-1": time.Now().UTC()})
	}))
	defer ts.Close()

	rc := &revocationCache{entries: map[string]time.Time{}}
	if err := rc.refresh(ts.URL); err != nil {
		t.Fatal(err)
	}
	if !rc.contains("rev-1") {
		t.Fatal("expected revocation to be present")
	}
	if rc.size() != 1 {
		t.Fatalf("expected size 1, got %d", rc.size())
	}
}
