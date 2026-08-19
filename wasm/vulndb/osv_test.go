package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

func TestNormalizeEcosystem(t *testing.T) {
	cases := map[string]string{
		"npm": EcosystemNPM, "NPM": EcosystemNPM, "node": EcosystemNPM,
		"composer": EcosystemPackagist, "php": EcosystemPackagist, "Packagist": EcosystemPackagist,
		"dart": EcosystemPub, "flutter": EcosystemPub, "pub": EcosystemPub,
	}
	for in, want := range cases {
		got, err := normalizeEcosystem(in)
		if err != nil || got != want {
			t.Errorf("normalizeEcosystem(%q) = %q,%v — want %q", in, got, err, want)
		}
	}
	if _, err := normalizeEcosystem("maven"); err == nil {
		t.Error("an unknown ecosystem must fail loudly — a silent miss looks like an all-clear")
	}
}

// Der Kern des Plugins: aus mehreren Fix-Zweigen den richtigen wählen. Wer hier
// danebenliegt, schlägt einen Major-Upgrade vor, wo eine Patch-Version genügt.
func TestResolveFixPicksTheBranch(t *testing.T) {
	ranges := []osvRange{{
		Type: "ECOSYSTEM",
		Events: []map[string]string{
			{"introduced": "2.0.0"}, {"fixed": "2.4.5"},
			{"introduced": "3.0.0"}, {"fixed": "3.1.2"},
		},
	}}

	fixed, candidates, text := resolveFix(ranges, "2.3.0")
	if fixed != "2.4.5" {
		t.Errorf("version 2.3.0 → fixed = %q, want 2.4.5 (the 2.x branch)", fixed)
	}
	if candidates != nil {
		t.Errorf("the branch is certain — candidates must stay empty, got %v", candidates)
	}
	if !strings.Contains(text, ">=2.0.0 <2.4.5") {
		t.Errorf("range text = %q", text)
	}

	if fixed, _, _ := resolveFix(ranges, "3.0.5"); fixed != "3.1.2" {
		t.Errorf("version 3.0.5 → fixed = %q, want 3.1.2 (the 3.x branch)", fixed)
	}
}

// Ohne Obergrenze ist der Zweig offen: es gibt keinen Fix.
func TestResolveFixWithoutFix(t *testing.T) {
	ranges := []osvRange{{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "0"}}}}
	fixed, _, text := resolveFix(ranges, "1.0.0")
	if fixed != "" {
		t.Errorf("fixed = %q, want empty", fixed)
	}
	if !strings.Contains(text, "no fix known") {
		t.Errorf("range text = %q, must say that there is no fix", text)
	}
}

// Lässt sich die Version nicht vergleichen, darf KEINE Fix-Version behauptet
// werden — der Agent bekommt alle Kandidaten und entscheidet selbst.
func TestResolveFixUncomparableVersion(t *testing.T) {
	ranges := []osvRange{{
		Type:   "ECOSYSTEM",
		Events: []map[string]string{{"introduced": "0"}, {"fixed": "2.4.5"}},
	}}
	fixed, candidates, _ := resolveFix(ranges, "dev-master")
	if fixed != "" {
		t.Errorf("fixed = %q — an uncomparable version must not produce a claim", fixed)
	}
	if len(candidates) != 1 || candidates[0] != "2.4.5" {
		t.Errorf("candidates = %v, want [2.4.5]", candidates)
	}
}

// GIT-Bereiche sind Commit-Spannen und sagen über eine Paketversion nichts.
func TestResolveFixIgnoresGitRanges(t *testing.T) {
	ranges := []osvRange{
		{Type: "GIT", Events: []map[string]string{{"introduced": "abc123"}, {"fixed": "def456"}}},
		{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "0"}, {"fixed": "1.2.3"}}},
	}
	fixed, candidates, _ := resolveFix(ranges, "1.0.0")
	if fixed != "1.2.3" {
		t.Errorf("fixed = %q, want 1.2.3", fixed)
	}
	for _, c := range candidates {
		if c == "def456" {
			t.Error("a commit SHA must not appear as a fix version")
		}
	}
}

func TestToFindingPrefersCVE(t *testing.T) {
	v := osvVuln{
		ID:      "GHSA-35jh-r3h4-6jhm",
		Aliases: []string{"CVE-2021-23337"},
		Summary: "Command Injection in lodash",
		Severity: []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []osvAffected{{
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []map[string]string{
				{"introduced": "0"}, {"fixed": "4.17.21"},
			}}},
		}},
	}
	v.Affected[0].Package.Name = "lodash"
	v.Affected[0].Package.Ecosystem = EcosystemNPM
	v.DatabaseSpecific.Severity = "high"

	f := toFinding(Package{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20", Dependency: depTransitive}, v)
	if f.CVE != "CVE-2021-23337" {
		t.Errorf("cve = %q — the CVE is the key of the duplicate check and must be extracted", f.CVE)
	}
	if f.Fixed != "4.17.21" {
		t.Errorf("fixed = %q, want 4.17.21", f.Fixed)
	}
	if f.Severity != "HIGH" || f.CVSSVector == "" {
		t.Errorf("severity = %q, vector = %q", f.Severity, f.CVSSVector)
	}
	if f.Dependency != depTransitive {
		t.Errorf("the role must be carried through: %q", f.Dependency)
	}
	if f.Reference == "" {
		t.Error("without a reference the ticket has no evidence")
	}
}

// Ende zu Ende gegen eine nachgebildete OSV-API. Geprüft wird vor allem die
// POSITIONELLE Zuordnung: results[i] gehört zu queries[i], und ein Treffer, der
// dem falschen Paket zugeordnet wird, ist ein Ticket gegen ein unschuldiges
// Paket.
// stubFetch replaces the host for the length of one test. There is no
// http.Client to point at a local server any more: the module hands a URL to
// the host and gets an answer, so a test IS the host.
func stubFetch(t *testing.T, fn func(covey.Request) covey.Response) {
	t.Helper()
	old := doFetch
	doFetch = fn
	t.Cleanup(func() { doFetch = old })
}

func jsonResp(body string) covey.Response {
	return covey.Response{Status: 200, Body: json.RawMessage(body)}
}

func TestQueryPackagesAssignsHitsPositionally(t *testing.T) {
	stubFetch(t, func(req covey.Request) covey.Response {
		switch {
		case strings.HasSuffix(req.Path, "/v1/querybatch"):
			var body struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
				} `json:"queries"`
			}
			json.Unmarshal(req.Body, &body)
			out := `{"results":[`
			for i, q := range body.Queries {
				if i > 0 {
					out += ","
				}
				if q.Package.Name == "lodash" {
					out += `{"vulns":[{"id":"GHSA-x"}]}`
				} else {
					out += `{"vulns":[]}`
				}
			}
			return jsonResp(out + `]}`)
		case strings.HasSuffix(req.Path, "/v1/query"):
			return jsonResp(`{"vulns":[{"id":"GHSA-x","aliases":["CVE-2021-23337"],
			  "summary":"Command Injection","database_specific":{"severity":"high"},
			  "affected":[{"package":{"name":"lodash","ecosystem":"npm"},
			  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}]}`)
		default:
			t.Errorf("unexpected path %s", req.Path)
			return covey.Response{Status: 404}
		}
	})

	res, err := queryPackages([]Package{
		{Ecosystem: "npm", Name: "express", Version: "4.18.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagesScanned != 3 {
		t.Errorf("packages_scanned = %d, want 3", res.PackagesScanned)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Package != "lodash" {
		t.Errorf("the hit was assigned to %q instead of lodash", res.Findings[0].Package)
	}
	if res.Clean {
		t.Error("clean must be false when there is a finding")
	}
}

// An answer whose length does not match the request makes every assignment a
// guess. Then giving up is the only right answer.
func TestQueryPackagesRejectsMismatchedBatch(t *testing.T) {
	stubFetch(t, func(covey.Request) covey.Response {
		return jsonResp(`{"results":[{"vulns":[]}]}`) // one answer to two queries
	})
	_, err := queryPackages([]Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
	})
	if err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("expected an error about the positional assignment, got %v", err)
	}
}

// A blocked host is the commonest operating fault. The message has to name the
// egress allowlist, or the agent goes looking at the database.
func TestNetErrorNamesEgress(t *testing.T) {
	stubFetch(t, func(covey.Request) covey.Response {
		// What the host reports when the request could not be made at all.
		return covey.Response{Error: "dial tcp: connection refused"}
	})
	_, err := queryPackages([]Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("the error must name the egress allowlist: %v", err)
	}
}

// The other shape of the same fault: the egress proxy answers 403 with nothing
// in it, which is not what a vulnerability database ever sends.
func TestEmpty403NamesEgress(t *testing.T) {
	stubFetch(t, func(covey.Request) covey.Response {
		return covey.Response{Status: 403}
	})
	_, err := queryPackages([]Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("an empty 403 has to point at the allowlist: %v", err)
	}
}
