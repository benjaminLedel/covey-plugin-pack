// Command k8s is the Kubernetes target system as a WebAssembly module.
//
//	GOOS=wasip1 GOARCH=wasm go build -trimpath -o k8s.wasm .
//
// It gives an agent read access to a cluster — the observability half of
// operating one, not the control half. The split follows the deployment model:
// a GitOps cluster reconciles its state from a repository, so an agent that
// applied a manifest directly would either have it reverted on the next sync or
// cause drift somebody has to chase. The write path for such a cluster is the
// gitlab plugin — a merge request against the infrastructure repository,
// reviewed like every other change. What is missing, and what this adds, is the
// ability to LOOK: why is a pod restarting, what does its log say, does this
// namespace have a NetworkPolicy at all.
//
// What held it in the binary was the cluster CA, and the fix improved more than
// the packaging. The certificate used to arrive as an ACTION PARAMETER
// ({{secret:k8s_ca}} in ca_pem), which put it through the model's context, the
// guard-rail subject and the recording of every single call. It is brokered
// now, like the token: k8s_ca → target.Credential.CA, and the host builds the
// trust store. The parameter is gone.
//
// The authoritative limit is the cluster's own RBAC, not this plugin's scopes.
// A ServiceAccount bound to `view` cannot delete a pod however the agent's
// ACCESS.md reads. Covey's scopes shape what an agent is TOLD it can do;
// Kubernetes decides what it can actually do. Both matter, in that order.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

func main() { covey.Run(plugin{}) }

type plugin struct{}

type params struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Selector   string `json:"selector"`
	Container  string `json:"container"`
	TailLines  int    `json:"tail_lines"`
	Previous   bool   `json:"previous"`
	Limit      int    `json:"limit"`
	Deployment string `json:"deployment"`
	// No ca_pem. It was here because the compiled plugin dialled for itself;
	// the host brokers the certificate now and the agent never handles one.
}

func (plugin) Describe() covey.Description {
	return covey.Description{
		Name:     "k8s",
		Label:    "Kubernetes",
		Category: "dev",
		Description: "Read a Kubernetes cluster: pod states and restarts, container logs (including the " +
			"previous, crashed container), events, workloads, Ingresses, and the objects a security " +
			"review needs (RBAC, NetworkPolicies, ServiceAccounts). Secrets are never readable. " +
			"Writes are deliberately limited to two operational actions (restart a Deployment, delete a " +
			"stuck Pod) because a GitOps cluster takes its desired state from the infrastructure " +
			"repository — everything else goes there as a merge request.",
		Scopes: []string{"read", "logs", "write"},
		Probe:  true,
		Actions: []covey.ActionDesc{
			{Name: "namespaces", Scope: "read", Doc: `{} — every namespace with its phase. The cheapest way to find out what the token can see at all.`},
			{Name: "pods", Scope: "read", Doc: `{"namespace":"prod","selector":"app=api"} — the projection kubectl get pods shows: phase, readiness, restarts, image, node.`},
			{Name: "get", Scope: "read", Doc: `{"namespace":"prod","kind":"deployment","name":"api"} — one object, projected to what is worth reading.`},
			{Name: "list", Scope: "read", Doc: `{"namespace":"prod","kind":"ingress"} — every object of a kind. Also rbac, networkpolicy, serviceaccount for a security review.`},
			{Name: "events", Scope: "read", Doc: `{"namespace":"prod","limit":50} — the namespace's events, newest first. Usually says why a pod will not start.`},
			{Name: "logs", Scope: "logs", Doc: `{"namespace":"prod","name":"api-7d9","container":"api","tail_lines":200,"previous":true} — container logs. previous:true reads the CRASHED container, which is where the cause is. A separate scope because a log can contain anything the application printed.`},
			{Name: "restart", Scope: "write", Doc: `{"namespace":"prod","deployment":"api"} — rollout restart, the same annotation bump kubectl writes. Safe against GitOps: the desired state in git is unchanged.`},
			{Name: "delete_pod", Scope: "write", Doc: `{"namespace":"prod","name":"api-7d9"} — delete one stuck pod so its controller recreates it. Pair it with a guard rail if that should stay a human decision.`},
		},
	}
}

func (plugin) Execute(action string, raw json.RawMessage) (any, error) {
	var in params
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}
	c := &client{}

	switch action {
	case "namespaces":
		return c.namespaces()
	case "pods":
		return c.pods(in)
	case "logs":
		return c.logs(in)
	case "events":
		return c.events(in)
	case "get":
		return c.get(in)
	case "list":
		return c.list(in)
	case "restart":
		return c.restart(in)
	case "delete_pod":
		return c.deletePod(in)
	default:
		return nil, fmt.Errorf("unknown action %q", action)
	}
}

// Probe answers what an operator actually wants to know after storing a token:
// does it reach the API server, and what may it see. Listing namespaces is the
// cheapest read that proves both — and when RBAC refuses it, the message the
// API server writes says which verb is missing, which is more useful than a
// generic failure.
func (plugin) Probe() (string, error) {
	var out struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := getJSON("/api/v1/namespaces", nil, &out); err != nil {
		return "", err
	}
	switch len(out.Items) {
	case 0:
		return "reachable, but the token sees no namespace", nil
	case 1:
		return "namespace " + out.Items[0].Metadata.Name, nil
	default:
		return fmt.Sprintf("%d namespaces, first %s", len(out.Items), out.Items[0].Metadata.Name), nil
	}
}
