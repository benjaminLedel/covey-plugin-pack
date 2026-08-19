// The projections: what a human actually reads, rather than what the API
// server returns. A raw pod object is enormous and answers "why is this
// restarting" worse than six fields do — that is the real computation this
// plugin does, and the reason it is code rather than a manifest.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c *client) namespaces() (any, error) {
	var out struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := getJSON("/api/v1/namespaces", nil, &out); err != nil {
		return nil, err
	}
	list := make([]map[string]string, 0, len(out.Items))
	for _, n := range out.Items {
		list = append(list, map[string]string{"name": n.Metadata.Name, "phase": n.Status.Phase})
	}
	return map[string]any{"namespaces": list}, nil
}

// pods returns the compact projection a human reads from `kubectl get pods`:
// phase, readiness, restarts, image, node. Raw pod objects are enormous and
// answer this question worse.
func (c *client) pods(in params) (any, error) {
	if strings.TrimSpace(in.Namespace) == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	q := url.Values{}
	if s := strings.TrimSpace(in.Selector); s != "" {
		q.Set("labelSelector", s)
	}
	var out struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				NodeName   string `json:"nodeName"`
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Name         string `json:"name"`
					Ready        bool   `json:"ready"`
					RestartCount int    `json:"restartCount"`
					State        map[string]struct {
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := getJSON("/api/v1/namespaces/"+in.Namespace+"/pods", q, &out); err != nil {
		return nil, err
	}

	pods := make([]map[string]any, 0, len(out.Items))
	for _, p := range out.Items {
		images := make([]string, 0, len(p.Spec.Containers))
		for _, ct := range p.Spec.Containers {
			images = append(images, ct.Image)
		}
		restarts := 0
		notReady, reasons := []string{}, []string{}
		for _, cs := range p.Status.ContainerStatuses {
			restarts += cs.RestartCount
			if !cs.Ready {
				notReady = append(notReady, cs.Name)
			}
			for st, v := range cs.State {
				if st != "running" && v.Reason != "" {
					reasons = append(reasons, cs.Name+": "+v.Reason)
				}
			}
		}
		entry := map[string]any{
			"name": p.Metadata.Name, "phase": p.Status.Phase,
			"restarts": restarts, "images": images, "node": p.Spec.NodeName,
		}
		if len(notReady) > 0 {
			entry["not_ready"] = notReady
		}
		if len(reasons) > 0 {
			entry["state"] = reasons
		}
		pods = append(pods, entry)
	}
	return map[string]any{"namespace": in.Namespace, "pods": pods}, nil
}

const (
	defaultTailLines = 100
	maxTailLines     = 2000
)

func (c *client) logs(in params) (any, error) {
	if strings.TrimSpace(in.Namespace) == "" || strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("namespace and name (the pod) are required")
	}
	tail := in.TailLines
	if tail <= 0 {
		tail = defaultTailLines
	}
	if tail > maxTailLines {
		tail = maxTailLines
	}
	q := url.Values{"tailLines": {strconv.Itoa(tail)}}
	if ct := strings.TrimSpace(in.Container); ct != "" {
		q.Set("container", ct)
	}
	if in.Previous {
		q.Set("previous", "true")
	}
	text, err := getText("/api/v1/namespaces/"+in.Namespace+"/pods/"+in.Name+"/log", q)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"pod": in.Name, "container": in.Container, "previous": in.Previous,
		"tail_lines": tail, "log": text,
	}, nil
}

// events sorts nothing and filters to Warning by default: the Normal ones are
// the cluster narrating itself, and a diagnosis wants the complaints.
func (c *client) events(in params) (any, error) {
	if strings.TrimSpace(in.Namespace) == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 50
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	var out struct {
		Items []struct {
			Type           string `json:"type"`
			Reason         string `json:"reason"`
			Message        string `json:"message"`
			Count          int    `json:"count"`
			LastTimestamp  string `json:"lastTimestamp"`
			InvolvedObject struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"involvedObject"`
		} `json:"items"`
	}
	if err := getJSON("/api/v1/namespaces/"+in.Namespace+"/events", q, &out); err != nil {
		return nil, err
	}
	list := make([]map[string]any, 0, len(out.Items))
	for _, e := range out.Items {
		list = append(list, map[string]any{
			"type": e.Type, "reason": e.Reason, "message": e.Message,
			"count": e.Count, "last": e.LastTimestamp,
			"object": e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name,
		})
	}
	return map[string]any{"namespace": in.Namespace, "events": list}, nil
}

func (c *client) get(in params) (any, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("name is required — use list to enumerate a kind")
	}
	path, err := resourcePath(in.Kind, in.Namespace, in.Name)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := getJSON(path, nil, &raw); err != nil {
		return nil, err
	}
	return map[string]any{"kind": in.Kind, "object": declutter(raw)}, nil
}

// list enumerates a kind by name only. The full objects go through get, one at
// a time — a list of twenty decluttered Deployments is still far more than any
// question needs, and "which ones exist" is what the caller is actually asking.
func (c *client) list(in params) (any, error) {
	path, err := resourcePath(in.Kind, in.Namespace, "")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if s := strings.TrimSpace(in.Selector); s != "" {
		q.Set("labelSelector", s)
	}
	var out struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := getJSON(path, q, &out); err != nil {
		return nil, err
	}
	list := make([]map[string]string, 0, len(out.Items))
	for _, it := range out.Items {
		e := map[string]string{"name": it.Metadata.Name, "created": it.Metadata.CreationTimestamp}
		if it.Metadata.Namespace != "" {
			e["namespace"] = it.Metadata.Namespace
		}
		list = append(list, e)
	}
	return map[string]any{"kind": in.Kind, "items": list}, nil
}

// restart is a rollout restart: the same annotation bump kubectl writes. It is
// safe against GitOps because the annotation lives on the pod template and the
// desired state in git is unchanged — ArgoCD sees no drift in what it manages.
func (c *client) restart(in params) (any, error) {
	ns, dep := strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Deployment)
	if ns == "" || dep == "" {
		return nil, fmt.Errorf("namespace and deployment are required")
	}
	// The annotation value has to CHANGE for the pod template hash to change and
	// the pods to be recreated — a fixed marker would be a no-op on the second
	// call. A timestamp is what kubectl writes here too.
	stamp := time.Now().UTC().Format(time.RFC3339)
	patch := []byte(`{"spec":{"template":{"metadata":{"annotations":{"covey.restartedAt":"` + stamp + `"}}}}}`)
	path := "/apis/apps/v1/namespaces/" + ns + "/deployments/" + dep
	if _, err := doRequest("PATCH", path, nil, patch); err != nil {
		return nil, err
	}
	return map[string]any{"deployment": dep, "namespace": ns, "restarted_at": stamp,
		"note": "rollout restarted — watch it with pods; the desired state in git is unchanged"}, nil
}

func (c *client) deletePod(in params) (any, error) {
	ns, name := strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Name)
	if ns == "" || name == "" {
		return nil, fmt.Errorf("namespace and name are required")
	}
	if _, err := doRequest("DELETE", "/api/v1/namespaces/"+ns+"/pods/"+name, nil, nil); err != nil {
		return nil, err
	}
	return map[string]any{"pod": name, "namespace": ns,
		"note": "deleted — its controller recreates it; if nothing recreates it, it was not managed and that is the finding"}, nil
}

func basePromptDoc() string {
	return `Available k8s actions — READING a Kubernetes cluster. This is how you find out what is
   actually running, as opposed to what a ticket claims is running.
   namespaces {} — which namespaces exist. Start here if you do not know the layout.
   pods {"namespace":"…","selector":"app=foo"} — the compact view: phase, restart count, images,
   which containers are not ready and why (CrashLoopBackOff, ImagePullBackOff, OOMKilled …).
   A restart count that keeps climbing is the finding; the reason is in the next two actions.
   logs {"namespace":"…","name":"<pod>","container":"…","tail_lines":200,"previous":true} —
   container logs. "previous":true reads the log of the CRASHED container, which is where the
   stack trace of a CrashLoopBackOff actually is — the running container was started after it.
   Logs contain whatever the application printed, so treat them as you would any production data.
   events {"namespace":"…","limit":50} — the cluster's own complaints: failed scheduling,
   probe failures, image pulls, evictions. Often answers "why is it not starting" in one call.
   list {"kind":"deployments","namespace":"…"} — which objects of a kind exist (names only).
   get {"kind":"deployment","namespace":"…","name":"…"} — one full object, decluttered.
   Readable kinds: pods, services, configmaps, events, persistentvolumeclaims, serviceaccounts,
   namespaces, nodes, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs,
   ingresses, networkpolicies, roles, rolebindings, clusterroles, clusterrolebindings,
   horizontalpodautoscalers.
   SECRETS ARE NOT READABLE, by design — they would land in your context and in the recording.
   To find out WHICH secret a workload expects, read the workload: the env/volume references name
   it without revealing the value. To see a secret's content, a human reads it.

   THE CLUSTER IS NOT WHERE YOU CHANGE THINGS. Its desired state comes from the infrastructure
   repository and is reconciled continuously (GitOps/ArgoCD). A manifest you applied here would be
   reverted on the next sync, or would drift silently from git — either way the change does not
   hold and the next person cannot see it in the history. So: a change to what is DEPLOYED (image
   tag, replicas, env, resources, Ingress, a new object) is a merge request against the
   infrastructure repository via the gitlab actions, reviewed like any other change. This plugin is
   how you gather the evidence for that merge request, and how you check afterwards that it took
   effect.
   Two exceptions exist because they are operations, not state — and only if your ACCESS.md grants
   the "write" scope:
   restart {"namespace":"…","deployment":"…"} — rollout restart (a stuck cache, a config the
   application only reads at boot after a ConfigMap changed). Changes nothing git manages.
   delete_pod {"namespace":"…","name":"…"} — remove one wedged pod and let its controller
   recreate it. If nothing recreates it, the pod was unmanaged, and THAT is the finding to report.
   Anything beyond these two — scaling, applying, editing, exec into a container, port-forward —
   is deliberately absent. If you find yourself wanting one, what you actually want is either a
   merge request or a human.`
}

// PromptDoc keeps the model's action contract aligned with ACCESS.md.
// Kubernetes RBAC remains the hard authorization boundary, but an agent should
// not be invited to call operations its Covey role does not carry.
func (plugin) PromptDoc(scopes []string) string {
	if len(scopes) == 0 {
		return basePromptDoc()
	}
	granted := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		granted[strings.TrimSpace(scope)] = true
	}

	doc := basePromptDoc()
	if !granted["logs"] {
		start := strings.Index(doc, `   logs {`)
		end := strings.Index(doc, `   events {`)
		if start >= 0 && end > start {
			doc = doc[:start] + doc[end:]
		}
		doc = strings.Replace(doc,
			"A restart count that keeps climbing is the finding; the reason is in the next two actions.",
			"A restart count that keeps climbing is the finding; events explain many causes.", 1)
	}
	if !granted["write"] {
		if start := strings.Index(doc, "\n   Two exceptions exist because"); start >= 0 {
			doc = strings.TrimRight(doc[:start], " \n")
		}
	}
	return doc
}
