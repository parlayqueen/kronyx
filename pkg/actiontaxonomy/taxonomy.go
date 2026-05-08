package actiontaxonomy

import "time"

type RiskClass string

type ApprovalMode string

type ReplayPolicy string

const (
	RiskLow      RiskClass    = "low"
	RiskHigh     RiskClass    = "high"
	ApprovalAuto ApprovalMode = "auto"
	ApprovalTwo  ApprovalMode = "two_person"
	ReplaySingle ReplayPolicy = "single_use"
)

type ActionSpec struct {
	Type         string        `json:"type"`
	Required     []string      `json:"required"`
	AllowedBound []string      `json:"allowed_bounds"`
	Risk         RiskClass     `json:"risk_class"`
	DefaultTTL   time.Duration `json:"default_ttl"`
	Approval     ApprovalMode  `json:"approval_mode"`
	Replay       ReplayPolicy  `json:"replay_policy"`
}

var Builtins = map[string]ActionSpec{
	"iam.rotate_prod_credentials": {
		Type: "iam.rotate_prod_credentials", Required: []string{"target_role", "ticket_id"}, AllowedBound: []string{"region", "max_impact"}, Risk: RiskHigh, DefaultTTL: 5 * time.Minute, Approval: ApprovalTwo, Replay: ReplaySingle,
	},
	"payments.initiate_wire": {
		Type: "payments.initiate_wire", Required: []string{"amount", "currency", "beneficiary_id", "ticket_id"}, AllowedBound: []string{"daily_budget_usd"}, Risk: RiskHigh, DefaultTTL: 2 * time.Minute, Approval: ApprovalTwo, Replay: ReplaySingle,
	},
	"secrets.write": {
		Type: "secrets.write", Required: []string{"path", "kv"}, AllowedBound: []string{"namespace"}, Risk: RiskHigh, DefaultTTL: 3 * time.Minute, Approval: ApprovalTwo, Replay: ReplaySingle,
	},
	"deploy.promote_to_prod": {
		Type: "deploy.promote_to_prod", Required: []string{"service", "artifact", "from_env", "to_env"}, AllowedBound: []string{"change_window"}, Risk: RiskHigh, DefaultTTL: 5 * time.Minute, Approval: ApprovalTwo, Replay: ReplaySingle,
	},
}
