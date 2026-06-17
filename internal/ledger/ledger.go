// Package ledger defines the engagement deployment ledger: a record of every
// mutation ENTRAITH pushes into a target tenant (app registrations, cloned
// groups, injected MFA methods, registered devices, Windows Hello keys, …),
// with enough metadata to undo it (a rollback descriptor), prove it (an
// exportable evidence trail), and detect it (the audit signature it triggers).
//
// It turns ad-hoc, memory-dependent cleanup into a guaranteed, auditable
// teardown — the operational hygiene any authorized engagement needs.
package ledger

import (
	"context"
	"errors"
	"time"
)

// Artifact types — the kind of object/mutation deployed into the tenant.
const (
	TypeAppRegistration    = "app_registration"
	TypeGroupClone         = "group_clone"
	TypeMFAMethod          = "mfa_method"
	TypeDeviceRegistration = "device_registration"
	TypeWinHelloKey        = "winhello_key"
	TypeCAPolicy           = "ca_policy"
	TypeSPCredential       = "sp_credential"
	TypeAppRoleAssignment  = "app_role_assignment"
	TypeRoleAssignment     = "role_assignment"
)

// Rollback kinds — how a deployed artifact is undone.
const (
	// RollbackGraph is an authenticated Microsoft Graph DELETE/PATCH against a
	// Graph-relative path. These are auto-executable by the teardown engine.
	RollbackGraph = "graph"
	// RollbackMySignIns is a My Sign-Ins MFA API call. Session-bound, so it is
	// surfaced for the operator instead of executed headlessly.
	RollbackMySignIns = "mysignins"
	// RollbackDRS targets the Device Registration Service. Surfaced as manual.
	RollbackDRS = "drs"
	// RollbackManual must be undone by hand; RollbackURL/Note carry instructions.
	RollbackManual = "manual"
)

// Status of a ledger entry.
const (
	StatusDeployed   = "deployed"
	StatusVerified   = "verified"
	StatusRolledBack = "rolled_back"
	StatusFailed     = "failed"
	StatusOrphaned   = "orphaned"
)

// ErrManual signals that an artifact cannot be auto-rolled-back and must be
// handled by the operator. The teardown engine records it as skipped_manual.
var ErrManual = errors.New("manual rollback required")

// Artifact is one deployed mutation recorded in the ledger.
type Artifact struct {
	ID         string `json:"id"`
	CampaignID string `json:"campaign_id"`
	TargetID   string `json:"target_id"`
	OperatorID string `json:"operator_id"`
	Type       string `json:"type"`
	TenantID   string `json:"tenant_id"`
	// ObjectID is the id of the object created in the tenant (e.g. application
	// object id, group id, device id) — the handle a rollback acts on.
	ObjectID    string `json:"object_id"`
	DisplayName string `json:"display_name"`

	// What created it — the exact call, for the evidence trail.
	ReqMethod string `json:"req_method"`
	ReqURL    string `json:"req_url"`
	ReqBody   string `json:"req_body"` // redacted; no secrets inline

	// How to undo it.
	RollbackKind   string `json:"rollback_kind"`
	RollbackMethod string `json:"rollback_method"`
	RollbackURL    string `json:"rollback_url"` // Graph-relative path (graph kind) or instructions
	RollbackBody   string `json:"rollback_body"`

	// DetectionSignature is the audit event this artifact triggers (purple-team
	// value): e.g. "Add application", "User registered security info".
	DetectionSignature string `json:"detection_signature"`
	// SecretRef points at where any secret material lives (table/id), never the
	// secret itself, so the ledger stays exportable.
	SecretRef string `json:"secret_ref"`

	Status       string     `json:"status"`
	Note         string     `json:"note"`
	CreatedAt    time.Time  `json:"created_at"`
	RolledBackAt *time.Time `json:"rolled_back_at,omitempty"`
}

// Rollbacker undoes a single artifact. It must return ErrManual for artifacts
// that cannot be auto-reverted (DRS / My Sign-Ins / manual kinds).
type Rollbacker func(ctx context.Context, a Artifact) error

// TeardownResult reports the outcome of one rollback attempt.
type TeardownResult struct {
	ArtifactID  string `json:"artifact_id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"` // rolled_back | failed | skipped_manual
	Detail      string `json:"detail"`
}

// Outcome statuses for TeardownResult.
const (
	OutcomeSkippedManual = "skipped_manual"
)

// Teardown walks artifacts (caller passes them newest-first so dependants are
// removed before their parents) and attempts to roll each one back. Already
// rolled-back entries are skipped. The caller persists status changes from the
// returned results. The function itself has no side effects beyond rb.
func Teardown(ctx context.Context, arts []Artifact, rb Rollbacker) []TeardownResult {
	out := make([]TeardownResult, 0, len(arts))
	for _, a := range arts {
		if a.Status == StatusRolledBack {
			continue
		}
		res := TeardownResult{ArtifactID: a.ID, Type: a.Type, DisplayName: a.DisplayName}
		err := rb(ctx, a)
		switch {
		case err == nil:
			res.Status = StatusRolledBack
		case errors.Is(err, ErrManual):
			res.Status = OutcomeSkippedManual
			res.Detail = a.RollbackMethod + " " + a.RollbackURL
			if a.Note != "" {
				res.Detail += " — " + a.Note
			}
		default:
			res.Status = StatusFailed
			res.Detail = err.Error()
		}
		out = append(out, res)
	}
	return out
}
