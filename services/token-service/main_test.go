package main

import (
	"os"
	"testing"
)

func TestRevocationPersistence(t *testing.T) {
	f, err := os.CreateTemp("", "kronyx-rev-*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)

	ks := newKeyset(path)
	if err := ks.revoke("abc"); err != nil {
		t.Fatal(err)
	}
	ks2 := newKeyset(path)
	if _, ok := ks2.revocationSnapshot()["abc"]; !ok {
		t.Fatal("expected persisted revocation key")
	}
}

func TestKeyRotation(t *testing.T) {
	ks := newKeyset("")
	old, _ := ks.activeKey()
	newKid, err := ks.rotateActiveKey()
	if err != nil {
		t.Fatal(err)
	}
	if newKid == old {
		t.Fatal("expected rotated key id to differ")
	}
	if _, ok := ks.publicJWK()["keys"]; !ok {
		t.Fatal("expected keys in jwk output")
	}
}
