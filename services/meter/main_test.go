package main

import (
	"os"
	"testing"
)

func TestBundleReload(t *testing.T) {
	f, err := os.CreateTemp("", "kronyx-policy-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`{"version":"v1","rules":[{"id":"r1","action_type":"deploy.promote_to_prod","env":"prod","allowed_groups":["sre"],"resource_prefix":"service/","required_attrs":{"mfa":"true"},"max_ttl_seconds":300,"required_phase":"change_window_open"}]}`)
	_ = f.Close()

	s := &bundleStore{path: f.Name()}
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	if s.get().Version != "v1" {
		t.Fatalf("expected v1, got %s", s.get().Version)
	}
}
