package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Subject struct {
	ID     string            `json:"id"`
	Attrs  map[string]string `json:"attrs"`
	Groups []string          `json:"groups"`
}

type ActionRequest struct {
	RequestID   string            `json:"request_id"`
	ActionType  string            `json:"action_type"`
	Resource    string            `json:"resource"`
	Env         string            `json:"env"`
	Subject     Subject           `json:"subject"`
	Payload     map[string]any    `json:"payload"`
	Bounds      map[string]string `json:"bounds"`
	Phase       string            `json:"phase"`
	RequestedAt time.Time         `json:"requested_at"`
}

type Rule struct {
	ID             string            `json:"id"`
	ActionType     string            `json:"action_type"`
	Env            string            `json:"env"`
	AllowedGroups  []string          `json:"allowed_groups"`
	ResourcePrefix string            `json:"resource_prefix"`
	RequiredAttrs  map[string]string `json:"required_attrs"`
	MaxTTLSeconds  int               `json:"max_ttl_seconds"`
	RequiredPhase  string            `json:"required_phase"`
}

type Bundle struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

type EvalResult struct {
	Decision    Decision          `json:"decision"`
	Reasons     []string          `json:"reasons"`
	Constraints map[string]string `json:"constraints"`
	RuleID      string            `json:"rule_id,omitempty"`
	Trace       []string          `json:"trace"`
}

func Evaluate(b Bundle, req ActionRequest) (EvalResult, error) {
	if req.ActionType == "" || req.Resource == "" || req.Subject.ID == "" {
		return EvalResult{}, errors.New("missing required action fields")
	}
	trace := []string{}
	for _, r := range b.Rules {
		trace = append(trace, fmt.Sprintf("checking rule=%s", r.ID))
		if r.ActionType != req.ActionType || r.Env != req.Env {
			trace = append(trace, "skip: action/env mismatch")
			continue
		}
		if r.RequiredPhase != "" && r.RequiredPhase != req.Phase {
			trace = append(trace, "skip: phase mismatch")
			continue
		}
		if r.ResourcePrefix != "" && !strings.HasPrefix(req.Resource, r.ResourcePrefix) {
			trace = append(trace, "skip: resource prefix mismatch")
			continue
		}
		if !containsGroup(req.Subject.Groups, r.AllowedGroups) {
			trace = append(trace, "skip: group mismatch")
			continue
		}
		for k, v := range r.RequiredAttrs {
			if req.Subject.Attrs[k] != v {
				return EvalResult{Decision: Deny, Reasons: []string{fmt.Sprintf("missing required attribute %s=%s", k, v)}, Trace: trace}, nil
			}
		}
		trace = append(trace, "allow")
		return EvalResult{Decision: Allow, RuleID: r.ID, Constraints: map[string]string{"max_ttl_seconds": fmt.Sprintf("%d", r.MaxTTLSeconds)}, Trace: trace}, nil
	}
	trace = append(trace, "deny:no matching allow rule")
	return EvalResult{Decision: Deny, Reasons: []string{"no matching allow rule"}, Trace: trace}, nil
}

func containsGroup(subject, allowed []string) bool {
	for _, s := range subject {
		for _, a := range allowed {
			if s == a {
				return true
			}
		}
	}
	return false
}
