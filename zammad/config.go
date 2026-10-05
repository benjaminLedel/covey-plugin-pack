package zammad

import (
	"fmt"
	"os"
	"strings"
)

// Operational configuration of the Zammad plugin from ENV (12-factor, like the
// webhook secrets in internal/config). Everything has safe defaults, so an
// unset field keeps the previous behaviour.
//
// Why ENV and not the DB: the built-in SecretStore and the webhook secrets
// already run through ENV, and the control plane is single-node in the MVP. A
// per-org configuration in the DB (several support queues on several agents) is
// the next step — see docs/ops-zammad.md, section "Outlook".

// intakeGroups returns the allowlist of Zammad groups (queues) whose tickets
// may trigger a task at all. Format:
//
//	COVEY_ZAMMAD_INTAKE_GROUPS="Support L1, Beschwerden"
//
// Empty/unset → no restriction (all groups). The comparison is case-insensitive,
// leading/trailing spaces are ignored.
func intakeGroups() map[string]bool {
	return parseSet(os.Getenv("COVEY_ZAMMAD_INTAKE_GROUPS"))
}

// externalReplyType determines the Zammad article type for customer-visible
// answers (internal=false). Default "email" — the answer goes to the customer
// by mail. Overridable for web/chat-based instances via
//
//	COVEY_ZAMMAD_REPLY_TYPE=web
//
// Internal notes (internal=true) are always type "note".
func externalReplyType() string {
	if t := strings.TrimSpace(os.Getenv("COVEY_ZAMMAD_REPLY_TYPE")); t != "" {
		return t
	}
	return "email"
}

// parseSet splits a comma-separated ENV list into a set of lower-cased, trimmed
// values. Empty entries are dropped.
func parseSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v != "" {
			out[v] = true
		}
	}
	return out
}

// Config is what the brokered zammad_url says beyond the address. The broker
// knows two secrets per system (zammad_url + zammad_token), so the URL carries
// the address plus optional components, separated by spaces, the way jira_url
// carries project= and salesforce_url carries queue=:
//
//	zammad_url = https://helpdesk.example.com [owner="<login or e-mail>"]
//
// owner= names whose queue this agent works: the tickets assigned to that
// Zammad user are what list_tickets returns by default and what the heartbeat
// pre-check looks at. Without it the queue is the token's own user — the
// natural case when the agent has a Zammad account of its own and people
// assign tickets to it like to any colleague. With it, a person can route
// tickets to the agent by assigning them to themselves, and the agent still
// sees what it takes over (the pre-check covers both owners).
type Config struct {
	BaseURL string // without a trailing slash and without /api/v1
	Owner   string // login or e-mail of the queue owner; empty = the token's user
}

// ParseConfig breaks zammad_url into the address and its components. Unknown
// components are an error rather than ignored: a typo in owner= would
// otherwise silently turn into "the token's own user", and the agent would
// work the wrong queue without anybody noticing.
func ParseConfig(baseURL string) (Config, error) {
	var cfg Config
	for _, part := range splitComponents(baseURL) {
		switch {
		case strings.HasPrefix(part, "owner="):
			cfg.Owner = strings.TrimSpace(strings.Trim(strings.TrimPrefix(part, "owner="), `"`))
		case cfg.BaseURL == "":
			cfg.BaseURL = strings.TrimRight(part, "/")
		default:
			return Config{}, fmt.Errorf(`zammad_url: unexpected component %q (expected: https://helpdesk.example.com [owner="<login or e-mail>"])`, part)
		}
	}
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("zammad_url: address missing (e.g. https://helpdesk.example.com)")
	}
	// The address with /api/v1 already on it is the mistake everybody makes
	// once. Cutting it is friendlier than a 404 on the first call.
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/api/v1")
	return cfg, nil
}

// splitComponents cuts zammad_url into its space-separated components —
// strings.Fields, except that a double-quoted run stays together, because an
// owner can be typed as owner="Ada Lovelace".
func splitComponents(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case !quoted && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}
