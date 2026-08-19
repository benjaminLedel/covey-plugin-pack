package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSecretsAreNeverReadable is the test that matters most in this package. A
// token bound too broadly (or a future ClusterRole change) must not turn this
// plugin into a way to copy every credential in the cluster into a run's
// context and its recording. The refusal has to happen HERE, before any
// request, and it has to explain itself — a bare "unknown kind" would read like
// a typo and invite the agent to try spellings.
func TestSecretsAreNeverReadable(t *testing.T) {
	for _, kind := range []string{"secrets", "Secrets", "SECRETS", "secret", "sealedsecrets"} {
		path, err := resourcePath(kind, "default", "some-secret")
		if err == nil {
			t.Fatalf("resourcePath(%q) returned a path (%q) — secrets must never be readable", kind, path)
		}
		if !strings.Contains(err.Error(), "secret") && !strings.Contains(err.Error(), "Secret") &&
			!strings.Contains(err.Error(), "SealedSecret") {
			t.Errorf("resourcePath(%q) refused, but the reason does not mention secrets: %v", kind, err)
		}
	}
	// The refusal must not depend on a namespace being supplied.
	if _, err := resourcePath("secrets", "", ""); err == nil {
		t.Error("a cluster-wide secrets listing must be refused too")
	}
}

func TestResourcePath(t *testing.T) {
	cases := []struct {
		kind, ns, name, want string
	}{
		{"pods", "prod", "web-0", "/api/v1/namespaces/prod/pods/web-0"},
		{"pods", "prod", "", "/api/v1/namespaces/prod/pods"},
		{"deployments", "prod", "web", "/apis/apps/v1/namespaces/prod/deployments/web"},
		{"ingresses", "prod", "", "/apis/networking.k8s.io/v1/namespaces/prod/ingresses"},
		{"networkpolicies", "prod", "", "/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies"},
		{"nodes", "", "node-1", "/api/v1/nodes/node-1"},
		{"clusterrolebindings", "", "", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
		{"  Deployments  ", "prod", "web", "/apis/apps/v1/namespaces/prod/deployments/web"},
	}
	for _, c := range cases {
		got, err := resourcePath(c.kind, c.ns, c.name)
		if err != nil {
			t.Errorf("resourcePath(%q,%q,%q): %v", c.kind, c.ns, c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("resourcePath(%q,%q,%q) = %q, want %q", c.kind, c.ns, c.name, got, c.want)
		}
	}

	// A namespaced kind without a namespace would otherwise silently read across
	// the whole cluster — that is a different question from the one asked.
	if _, err := resourcePath("pods", "", "web-0"); err == nil {
		t.Error("a namespaced kind without a namespace must be refused")
	}
	// And the reverse: a namespace on a cluster-scoped kind means the caller has
	// the wrong mental model and should hear about it.
	if _, err := resourcePath("nodes", "prod", ""); err == nil {
		t.Error("a namespace on a cluster-scoped kind must be refused")
	}
	if _, err := resourcePath("customresourcedefinitions", "", ""); err == nil {
		t.Error("a kind outside the allowlist must be refused")
	}
}

// TestNewClientRefusesUnverifiedTLS: there is no opt-out from certificate
// verification, and the failure modes that would tempt someone to add one have
// to fail loudly instead.
func TestDeclutter(t *testing.T) {
	raw := []byte(`{
	  "metadata": {
	    "name": "web",
	    "managedFields": [{"manager":"kubectl","fieldsV1":{"f:spec":{}}}],
	    "annotations": {
	      "kubectl.kubernetes.io/last-applied-configuration": "{\"a\":1}",
	      "keep.me/please": "yes"
	    }
	  },
	  "spec": {"replicas": 2}
	}`)
	var got map[string]any
	if err := json.Unmarshal(declutter(raw), &got); err != nil {
		t.Fatal(err)
	}
	md := got["metadata"].(map[string]any)
	if _, ok := md["managedFields"]; ok {
		t.Error("managedFields survived")
	}
	ann := md["annotations"].(map[string]any)
	if _, ok := ann["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Error("last-applied-configuration survived")
	}
	if ann["keep.me/please"] != "yes" {
		t.Error("an unrelated annotation was removed — only the two noisy ones may go")
	}
	if md["name"] != "web" {
		t.Error("name was lost")
	}
	if got["spec"].(map[string]any)["replicas"].(float64) != 2 {
		t.Error("spec was altered")
	}

	// Lists get the same treatment per item, otherwise a `list` of twenty pods
	// carries twenty managedFields blocks.
	rawList := []byte(`{"items":[{"metadata":{"name":"a","managedFields":[{"m":1}]}}]}`)
	var gotList map[string]any
	if err := json.Unmarshal(declutter(rawList), &gotList); err != nil {
		t.Fatal(err)
	}
	item := gotList["items"].([]any)[0].(map[string]any)["metadata"].(map[string]any)
	if _, ok := item["managedFields"]; ok {
		t.Error("managedFields survived inside a list item")
	}

	// Malformed input must pass through rather than blank the answer.
	if string(declutter([]byte("not json"))) != "not json" {
		t.Error("unparseable input must be returned unchanged")
	}
}

// TestExecuteRejectsBadInputBeforeDialling: every action validates its
// arguments before a request goes out, so a missing namespace is an immediate,
// readable error rather than a call against the wrong scope.
func TestPromptDocNamesTheGitOpsRule(t *testing.T) {
	doc := basePromptDoc()
	for _, want := range []string{"merge request", "SECRETS ARE NOT READABLE", "previous"} {
		if !strings.Contains(doc, want) {
			t.Errorf("PromptDoc does not mention %q", want)
		}
	}
}

func TestPromptDocForScopesReadOnlyHidesLogsAndWrites(t *testing.T) {
	doc := (plugin{}).PromptDoc([]string{"read"})
	for _, phrase := range []string{"pods {", "events {", "list {", "get {", "merge request"} {
		if !strings.Contains(doc, phrase) {
			t.Errorf("read-only prompt doc must include %q", phrase)
		}
	}
	for _, phrase := range []string{"logs {", "restart {", "delete_pod {"} {
		if strings.Contains(doc, phrase) {
			t.Errorf("read-only prompt doc must hide %q", phrase)
		}
	}
}

func TestPromptDocForScopesAddsOnlyGrantedCapabilities(t *testing.T) {
	logsDoc := (plugin{}).PromptDoc([]string{"read", "logs"})
	if !strings.Contains(logsDoc, "logs {") {
		t.Fatal("logs scope must add the logs action")
	}
	for _, phrase := range []string{"restart {", "delete_pod {"} {
		if strings.Contains(logsDoc, phrase) {
			t.Errorf("logs scope must not add write action %q", phrase)
		}
	}

	writeDoc := (plugin{}).PromptDoc([]string{"read", "write"})
	for _, phrase := range []string{"restart {", "delete_pod {"} {
		if !strings.Contains(writeDoc, phrase) {
			t.Errorf("write scope must add %q", phrase)
		}
	}
	if strings.Contains(writeDoc, "logs {") {
		t.Error("write scope alone must not add the logs action")
	}
}

func TestPromptDocForScopesEmptyAndFullStayCompatible(t *testing.T) {
	full := basePromptDoc()
	if got := (plugin{}).PromptDoc(nil); got != full {
		t.Fatal("an empty scope list must fail open to the full prompt doc")
	}
	if got := (plugin{}).PromptDoc([]string{"read", "logs", "write"}); got != full {
		t.Fatal("all scopes must produce the unchanged full prompt doc")
	}
}
