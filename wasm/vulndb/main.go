// Command vulndb is the vulnerability-database target system as a WebAssembly
// module.
//
//	GOOS=wasip1 GOARCH=wasm go build -trimpath -o vulndb.wasm .
//
// What held this plugin in the binary was scan_lockfile: judging what a project
// declares means reading the lock file the project actually has, and a module
// had no way to. The protocol has one now (read_file), and the confinement
// improved in the move — the host resolves the path inside the workspace with
// os.Root, so a way out fails at the syscall instead of in a string check this
// plugin used to carry itself.
//
// It is the odd one among the three in a way worth stating: it has no brokered
// system at all. All six sources are public, so the module declares them as
// hosts and runs with no credential — there is nothing here to leak.
package main

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

func main() { covey.Run(plugin{}) }

type plugin struct{}

func (plugin) Describe() covey.Description {
	return covey.Description{
		Name:        "vulndb",
		Label:       "Vulnerability databases",
		Description: "Known vulnerabilities in declared package dependencies: scan a lock file (package-lock.json, composer.lock, pubspec.lock) against OSV.dev in one batch (scan_lockfile), check individual packages (query/query_batch), fetch an advisory merged from OSV, the GitHub Advisory Database and NVD (advisory), and look up the next safe version in the registry (latest_version). Covers npm, Packagist (Composer) and Pub (Dart/Flutter). Needs no credentials — every source is public.",
		Category:    "dev",
		Scopes:      []string{"read"},
		// Declared, not reached at runtime: an operator sees the whole list
		// before installing. They are also exactly the hosts that have to be
		// in the egress allowlist, and naming them here is what lets the store
		// say so instead of leaving it to a failed action.
		Hosts: []string{
			"api.osv.dev",
			"api.github.com",
			"services.nvd.nist.gov",
			"registry.npmjs.org",
			"repo.packagist.org",
			"pub.dev",
		},
		// scan_lockfile reads the agent's checkout. Without the declaration a
		// read_file is refused.
		Workdir: true,
		Actions: []covey.ActionDesc{
			{Name: "scan_lockfile", Scope: "read", Doc: `{"path":"repo/package-lock.json"} — the main action: read the lock file out of your checkout and match every installed version against OSV.dev in one batch.`},
			{Name: "query_batch", Scope: "read", Doc: `{"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.20"}]} — the same check for pairs you determined yourself. The way for yarn.lock and pnpm-lock.yaml.`},
			{Name: "query", Scope: "read", Doc: `{"ecosystem":"npm","name":"lodash","version":"4.17.20"} — a single package.`},
			{Name: "advisory", Scope: "read", Doc: `{"id":"CVE-2021-23337"} — one advisory in full, merged from OSV, the GitHub Advisory Database and NVD. Also takes GHSA-… and OSV ids.`},
			{Name: "latest_version", Scope: "read", Doc: `{"ecosystem":"npm","name":"lodash"} — the registry's version list: does the proposed fix version exist, and what has appeared since?`},
		},
	}
}

func (plugin) Execute(action string, params json.RawMessage) (any, error) {
	var in struct {
		Path      string    `json:"path"`
		Ecosystem string    `json:"ecosystem"`
		Name      string    `json:"name"`
		Version   string    `json:"version"`
		ID        string    `json:"id"`
		Packages  []Package `json:"packages"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
	case "scan_lockfile":
		return scanLockfile(in.Path)
	case "query_batch":
		return queryPackages(in.Packages)
	case "query":
		eco, err := normalizeEcosystem(in.Ecosystem)
		if err != nil {
			return nil, err
		}
		return queryPackages([]Package{{Ecosystem: eco, Name: in.Name, Version: in.Version}})
	case "advisory":
		return lookupAdvisory(in.ID)
	case "latest_version":
		eco, err := normalizeEcosystem(in.Ecosystem)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.Name) == "" {
			return nil, fmt.Errorf("name missing")
		}
		return fetchVersions(eco, strings.TrimSpace(in.Name))
	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// ScanResult is the result of scan_lockfile.
type ScanResult struct {
	Lockfile        string    `json:"lockfile"`
	Ecosystem       string    `json:"ecosystem"`
	PackagesScanned int       `json:"packages_scanned"`
	Findings        []Finding `json:"findings"`
	// Clean says explicitly that something was checked and nothing found —
	// which is a different statement from an empty list because nothing could
	// be checked.
	Clean bool     `json:"clean"`
	Notes []string `json:"notes,omitempty"`
}

// scanLockfile reads one lock file out of the agent's workspace.
//
// The confinement is the host's now, and it is stronger than what this plugin
// used to do for itself: the host resolves the path inside the workspace with
// os.Root, so a symlink pointing out fails when it is opened rather than in a
// comparison somebody has to keep correct. What is left here is the early,
// legible error — "/etc/passwd" is refused by name instead of being quietly
// reinterpreted as a path inside the checkout, because a silent reinterpretation
// hides what was meant.
func scanLockfile(p string) (*ScanResult, error) {
	rel, err := relInWorkspace(p)
	if err != nil {
		return nil, err
	}
	text, err := covey.ReadFile(rel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}

	// The display name carries the relative path only — ParseLockfile decides
	// the type from it, and the result goes back to the agent.
	parsed, err := ParseLockfile(rel, []byte(text))
	if err != nil {
		return nil, err
	}
	res := &ScanResult{
		Lockfile: p, Ecosystem: parsed.Ecosystem,
		PackagesScanned: len(parsed.Packages), Notes: parsed.Notes,
	}

	findings, err := queryPackages(parsed.Packages)
	if err != nil {
		return nil, err
	}
	res.Findings = findings.Findings
	res.Notes = append(res.Notes, findings.Notes...)
	res.Clean = len(res.Findings) == 0 && len(res.Notes) == 0
	return res, nil
}

// relInWorkspace normalises the path the agent names and refuses anything that
// leads out. Absolute is deliberately an error rather than "made relative":
// whoever sends "/etc/passwd" does not mean "repo/etc/passwd".
func relInWorkspace(p string) (string, error) {
	s := strings.TrimSpace(p)
	if s == "" {
		return "", fmt.Errorf(`path missing — name the lock file, e.g. "repo/package-lock.json"`)
	}
	// Slash-separated on purpose: the path travels to a host that resolves it
	// inside the workspace, and the module has no filesystem to have a
	// separator of its own.
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) {
		return "", fmt.Errorf("path must be relative to your working directory, was %q — "+
			`name the lock file inside the checkout, e.g. "repo/package-lock.json"`, p)
	}
	c := path.Clean(strings.ReplaceAll(s, `\`, "/"))
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("path must not lead out of your working directory, was %q", p)
	}
	if c == "." {
		return "", fmt.Errorf("path names a directory, not a lock file: %q", p)
	}
	return c, nil
}

// BatchResult is the result of query/query_batch.
type BatchResult struct {
	PackagesScanned int       `json:"packages_scanned"`
	Findings        []Finding `json:"findings"`
	Clean           bool      `json:"clean"`
	Notes           []string  `json:"notes,omitempty"`
}

// queryPackages is the shared core: first one batch over all packages (which
// says WHICH are affected), then a detail query only for those. On a usual
// project that is a few percent — the other way round would be many times the
// calls.
func queryPackages(pkgs []Package) (*BatchResult, error) {
	res := &BatchResult{}
	clean := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		eco, err := normalizeEcosystem(p.Ecosystem)
		if err != nil {
			return nil, err
		}
		p.Ecosystem = eco
		p.Name = strings.TrimSpace(p.Name)
		p.Version = strings.TrimSpace(p.Version)
		if p.Name == "" || p.Version == "" {
			return nil, fmt.Errorf("package without a name or version: %+v", p)
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("no packages given")
	}
	res.PackagesScanned = len(clean)

	osv := newOSV()
	hits, err := osv.batch(clean)
	if err != nil {
		return nil, err
	}
	for i, hit := range hits {
		if !hit {
			continue
		}
		vulns, err := osv.query(clean[i])
		if err != nil {
			// A single failure must not make the scan worthless — but it must
			// not pass as "clean" either. So: a note that lands in the report.
			res.Notes = append(res.Notes, fmt.Sprintf("%s@%s: details not fetchable (%v) — the package IS affected, the finding is incomplete", clean[i].Name, clean[i].Version, err))
			continue
		}
		for _, v := range vulns {
			res.Findings = append(res.Findings, toFinding(clean[i], v))
		}
	}
	res.Clean = len(res.Findings) == 0 && len(res.Notes) == 0
	return res, nil
}

// lookupAdvisory merges the detail view from every source that answers. If one
// drops out that stands as a note in the result — a missing CVSS score is
// something other than a score of 0.
func lookupAdvisory(id string) (*Advisory, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("id missing — expected CVE-…, GHSA-… or an OSV ID")
	}
	var notes []string

	osvRec, err := newOSV().vuln(id)
	if err != nil {
		osvRec = nil
		notes = append(notes, sourceNote("osv", err))
	}

	// The GHSA id is either in the request or among the OSV record's aliases.
	ghsaID := ""
	if strings.HasPrefix(id, "GHSA-") {
		ghsaID = id
	} else if osvRec != nil {
		if strings.HasPrefix(osvRec.ID, "GHSA-") {
			ghsaID = osvRec.ID
		} else {
			for _, a := range osvRec.Aliases {
				if strings.HasPrefix(a, "GHSA-") {
					ghsaID = a
					break
				}
			}
		}
	}
	cve := id
	if !strings.HasPrefix(cve, "CVE-") {
		cve = ""
		if osvRec != nil {
			cve = pickCVE(*osvRec)
		}
	}

	var ghsa *ghsaAdvisory
	switch {
	case ghsaID != "":
		ghsa, err = fetchGHSA(ghsaID)
	case cve != "":
		ghsa, err = fetchGHSAByCVE(cve)
	default:
		err = errNotFound
	}
	if err != nil {
		ghsa = nil
		notes = append(notes, sourceNote("ghsa", err))
	}
	if cve == "" && ghsa != nil {
		cve = ghsa.CVEID
	}

	var score float64
	var severity, vector string
	if cve != "" {
		score, severity, vector, err = fetchNVD(cve)
		if err != nil {
			notes = append(notes, sourceNote("nvd", err))
		}
	} else {
		notes = append(notes, "nvd: not queried — no CVE number known for this advisory")
	}

	if osvRec == nil && ghsa == nil && vector == "" {
		return nil, fmt.Errorf("%s: no source answered — %s", id, strings.Join(notes, "; "))
	}
	a := mergeAdvisory(id, osvRec, ghsa, score, severity, vector)
	a.Notes = notes
	return &a, nil
}

// PromptDoc is worth writing out rather than leaving to the generated action
// list: it sits in the context of every turn, and the two sentences that stop
// an agent reporting a false all-clear ("clean":true versus an empty list with
// notes) are the ones that would be missing.
func (plugin) PromptDoc(scopes []string) string {
	return `Available vulndb actions — the known vulnerabilities of declared package dependencies.
   Covered ecosystems: npm, Packagist (Composer/PHP), Pub (Dart/Flutter). Write them exactly like
   that or in their common form (composer/php, dart/flutter) — the plugin normalises it.
   scan_lockfile {"path":"<the path to the lock file, relative to your working directory>"} —
   THE main action. Reads package-lock.json, npm-shrinkwrap.json, composer.lock or pubspec.lock,
   determines the installed versions and matches ALL of them against OSV.dev in one batch. The result:
   {"lockfile":…,"ecosystem":…,"packages_scanned":812,"clean":false,"findings":[…],"notes":[…]}.
   Use it after a checkout — the path is the checkout path plus the lock file. A monorepo has several;
   scan each one.
   Every finding carries what a ticket needs: package, version, dependency (direct/dev/transitive),
   id, cve, summary, severity, cvss_vector, affected_range, fixed and reference.
   READ "fixed" CAREFULLY: it is the fix version of the branch YOUR version sits on. An advisory often
   has several (2.4.5 for the 2.x line, 3.1.2 for 3.x) — the plugin picks the fitting one. If it stands
   empty and "fixed_candidates" is filled, the branch could NOT be determined (an unusual version
   scheme): then name the candidates in the ticket instead of picking one yourself.
   "clean":true means checked and nothing found. An empty findings list WITH notes means the opposite —
   something could not be checked. Never report that as an all-clear.
   query_batch {"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.20"},…]} — the same
   check for name/version pairs you determined yourself. That is the way for yarn.lock and
   pnpm-lock.yaml (they are deliberately not parsed: their format changes between major versions, and a
   half-read lock file reports fewer packages than there are) — pull the pairs out with the dev tool
   and send them through here.
   query {"ecosystem":"npm","name":"lodash","version":"4.17.20"} — a single package, the same result.
   advisory {"id":"CVE-2021-23337"} — the details of ONE advisory, merged from OSV, the GitHub Advisory
   Database and NVD: description, severity, cvss_vector, cvss_score, the affected packages with their
   first patched version, references. Also takes GHSA-… and OSV IDs. "sources" says who answered,
   "notes" who did not — a missing CVSS score is something other than a score of 0.
   Take it for every finding that is to become a ticket; scan_lockfile stays deliberately terse so that
   a scan over hundreds of packages does not flood your context.
   latest_version {"ecosystem":"npm","name":"lodash"} — the registry's version list: does the proposed
   fix version exist at all, and what has appeared since? Use it before you propose an upgrade.
   What this system does NOT do: it judges the DECLARED dependencies of a lock file. It finds neither
   vulnerabilities in your own code nor ones in container images, and without a lock file it cannot
   work — a manifest declares ranges, and a range is not a fact. If a project has no lock file, that is
   a finding of its own, not a clean result.
   Every call goes out through the egress proxy. If an action reports a host as unreachable, that host
   is missing from the allowlist — name it in your answer instead of retrying.`
}
