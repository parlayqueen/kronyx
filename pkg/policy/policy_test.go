package policy

import (
	"testing"
	"time"
)

func TestEvaluateAllow(t *testing.T) {
	bundle := Bundle{Version: "v1", Rules: []Rule{{ID: "r1", ActionType: "deploy.promote_to_prod", Env: "prod", AllowedGroups: []string{"sre"}, ResourcePrefix: "service/", RequiredAttrs: map[string]string{"mfa": "true"}, MaxTTLSeconds: 100, RequiredPhase: "change_window_open"}}}
	req := ActionRequest{RequestID: "1", ActionType: "deploy.promote_to_prod", Resource: "service/api", Env: "prod", Subject: Subject{ID: "u1", Attrs: map[string]string{"mfa": "true"}, Groups: []string{"sre"}}, Phase: "change_window_open", RequestedAt: time.Now()}
	res, err := Evaluate(bundle, req)
	if err != nil || res.Decision != Allow {
		t.Fatalf("unexpected: %#v err=%v", res, err)
	}
}
