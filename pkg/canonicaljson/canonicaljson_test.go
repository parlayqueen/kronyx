package canonicaljson

import "testing"

func TestMarshalDeterministic(t *testing.T) {
	a := map[string]any{"b": 1, "a": "x"}
	b := map[string]any{"a": "x", "b": 1}
	ca, _ := Marshal(a)
	cb, _ := Marshal(b)
	if string(ca) != string(cb) {
		t.Fatalf("expected deterministic canonical output")
	}
}
