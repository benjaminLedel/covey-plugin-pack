package vulndb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The Maven ordering, against the versions Maven projects actually publish.
// The cases that matter most are the ones semver gets wrong: ".Final" does
// not parse as semver at all, and "-jre" would rank as a pre-release.
func TestCompareMaven(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"2.21.4", "2.21.5", -1, true},
		{"6.2.10", "6.2.9", 1, true}, // numeric, not lexical
		{"9.0.98", "9.0.99", -1, true},
		{"9.0.98", "10.1.0", -1, true},
		{"2.13.4.2", "2.13.4", 1, true}, // a fourth segment counts
		{"1.0", "1.0.0", 0, true},
		{"1.0.0.Final", "1.0.0", 0, true}, // Final, GA and RELEASE are the release
		{"2.0.0.RELEASE", "2.0.0.GA", 0, true},
		{"5.4.20.Final", "5.4.24.Final", -1, true},
		{"1.0.0.CR1", "1.0.0.Final", -1, true},
		{"5.3.0.CR2", "5.3.0.CR1", 1, true},
		{"1.0.0-rc1", "1.0.0.CR1", 0, true}, // cr is rc
		{"1.0-alpha-1", "1.0-beta-1", -1, true},
		{"1.0-beta-1", "1.0-M1", -1, true},
		{"1.0-M1", "1.0-RC1", -1, true},
		{"1.0-RC1", "1.0-SNAPSHOT", -1, true},
		{"1.0-SNAPSHOT", "1.0", -1, true},
		{"1.0", "1.0-SP1", -1, true},
		{"1.0b2", "1.0rc1", -1, true}, // b followed by a number is beta
		{"2.14.0-rc2", "2.14.0", -1, true},
		{"33.4.0-jre", "33.4.0-jre", 0, true},
		{"33.4.0-jre", "32.0.0-android", 1, true}, // the core decides
		{"31.1-jre", "32.0.0-android", -1, true},
		{"1.0.0-jre", "1.0.1", -1, true},
		// No order, so no claim: two different unknown qualifiers on the same
		// core, an unknown qualifier against the release, and the shapes the
		// model does not cover.
		{"32.0.0-jre", "32.0.0-android", 0, false},
		{"33.4.0-jre", "33.4.0", 0, false},
		{"1.0-1", "1.0", 0, false},
		{"1.0.0-20240101.120000-3", "1.0.0", 0, false},
		{"1.0-jre-SNAPSHOT", "1.0", 0, false},
		{"1.0.Final2", "1.0", 0, false},
		{"r09", "1.0", 0, false},
		{"", "1.0", 0, false},
	}
	for _, c := range cases {
		got, ok := compareMaven(c.a, c.b)
		if ok != c.ok {
			t.Errorf("compareMaven(%q,%q) comparable = %v, want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("compareMaven(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: the other way round must say the opposite.
		if back, okBack := compareMaven(c.b, c.a); okBack != ok || (ok && back != -got) {
			t.Errorf("compareMaven(%q,%q) = %d,%v is not the reverse of %d,%v", c.b, c.a, back, okBack, got, ok)
		}
	}
}

// The fix branch for typical Maven advisories. Each of these would have come
// back as fixed_candidates under the semver comparison, or with the wrong
// branch.
func TestResolveFixMaven(t *testing.T) {
	cases := []struct {
		name      string
		events    []map[string]string
		installed string
		want      string
	}{
		{
			name: "jackson-databind, three lines",
			events: []map[string]string{
				{"introduced": "0"}, {"fixed": "2.12.7.1"},
				{"introduced": "2.13.0"}, {"fixed": "2.13.4.2"},
				{"introduced": "2.14.0-rc1"}, {"fixed": "2.14.0"},
			},
			installed: "2.13.3", want: "2.13.4.2",
		},
		{
			name: "jackson-databind, a release candidate",
			events: []map[string]string{
				{"introduced": "2.13.0"}, {"fixed": "2.13.4.2"},
				{"introduced": "2.14.0-rc1"}, {"fixed": "2.14.0"},
			},
			installed: "2.14.0-rc2", want: "2.14.0",
		},
		{
			name: "spring-webmvc, the 6.2 line",
			events: []map[string]string{
				{"introduced": "6.1.0"}, {"fixed": "6.1.22"},
				{"introduced": "6.2.0"}, {"fixed": "6.2.11"},
			},
			installed: "6.2.10", want: "6.2.11",
		},
		{
			name: "tomcat-embed-core, the 9.0 line",
			events: []map[string]string{
				{"introduced": "9.0.0.M1"}, {"fixed": "9.0.99"},
				{"introduced": "10.1.0-M1"}, {"fixed": "10.1.35"},
				{"introduced": "11.0.0-M1"}, {"fixed": "11.0.3"},
			},
			installed: "9.0.98", want: "9.0.99",
		},
		{
			name:      "hibernate-core, .Final versions",
			events:    []map[string]string{{"introduced": "0"}, {"fixed": "5.4.24.Final"}},
			installed: "5.4.20.Final", want: "5.4.24.Final",
		},
		{
			name:      "guava, -jre installed against an -android fix",
			events:    []map[string]string{{"introduced": "0"}, {"fixed": "32.0.0-android"}},
			installed: "31.1-jre", want: "32.0.0-android",
		},
		{
			name:      "a 1.0.0.Final line",
			events:    []map[string]string{{"introduced": "1.0.0.Final"}, {"fixed": "1.0.3.Final"}},
			installed: "1.0.0.Final", want: "1.0.3.Final",
		},
	}
	for _, c := range cases {
		ranges := []osvRange{{Type: "ECOSYSTEM", Events: c.events}}
		fixed, candidates, _ := resolveFix(EcosystemMaven, ranges, c.installed)
		if fixed != c.want {
			t.Errorf("%s: %s → fixed = %q, want %q", c.name, c.installed, fixed, c.want)
		}
		if candidates != nil {
			t.Errorf("%s: the branch is certain — candidates must stay empty, got %v", c.name, candidates)
		}
	}
}

// Where the Maven ordering has no answer, the existing fallback holds: no fix
// version is claimed, every candidate is named.
func TestResolveFixMavenFallsBack(t *testing.T) {
	ranges := []osvRange{{
		Type:   "ECOSYSTEM",
		Events: []map[string]string{{"introduced": "0"}, {"fixed": "32.0.0-android"}},
	}}
	// 32.0.0-jre against 32.0.0-android: the same core, two unknown
	// qualifiers. Maven would order them alphabetically; that is no fact.
	fixed, candidates, _ := resolveFix(EcosystemMaven, ranges, "32.0.0-jre")
	if fixed != "" {
		t.Errorf("fixed = %q — an undecidable order must not produce a claim", fixed)
	}
	if len(candidates) != 1 || candidates[0] != "32.0.0-android" {
		t.Errorf("candidates = %v, want [32.0.0-android]", candidates)
	}

	// A timestamped snapshot is outside the model.
	ranges = []osvRange{{
		Type:   "ECOSYSTEM",
		Events: []map[string]string{{"introduced": "0"}, {"fixed": "2.0.1"}, {"introduced": "3.0.0"}, {"fixed": "3.0.2"}},
	}}
	fixed, candidates, _ = resolveFix(EcosystemMaven, ranges, "2.0.0-20240101.120000-3")
	if fixed != "" || len(candidates) != 2 {
		t.Errorf("fixed = %q, candidates = %v — want no claim and both candidates", fixed, candidates)
	}
}

func TestMavenMetadataPath(t *testing.T) {
	got, err := mavenMetadataPath("com.fasterxml.jackson.core:jackson-databind")
	if err != nil || got != "com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml" {
		t.Errorf("path = %q, %v", got, err)
	}
	if got, err := mavenMetadataPath("org.apache.tomcat.embed:tomcat-embed-core"); err != nil || got != "org/apache/tomcat/embed/tomcat-embed-core/maven-metadata.xml" {
		t.Errorf("path = %q, %v", got, err)
	}
	// An artifactId may contain dots; the groupId's dots are the path.
	if got, _ := mavenMetadataPath("io.netty:netty-codec-http2"); got != "io/netty/netty-codec-http2/maven-metadata.xml" {
		t.Errorf("path = %q", got)
	}
	for _, bad := range []string{
		"jackson-databind", // no groupId
		"com.fasterxml.jackson.core:jackson-databind:2.18.2", // a version in the name
		"com..fasterxml:x", // an empty group segment
		":jackson-databind",
		"com.example:",
		"com.example:../../etc",
		"com/example:x",
		"com.example:x?y",
	} {
		if _, err := mavenMetadataPath(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		} else if !strings.Contains(err.Error(), "groupId:artifactId") {
			t.Errorf("%q: the error must name the expected form: %v", bad, err)
		}
	}
}

const jacksonMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <versioning>
    <latest>2.19.0-rc2</latest>
    <release>2.18.2</release>
    <versions>
      <version>2.9.10.8</version>
      <version>2.13.4.2</version>
      <version>2.18.2</version>
      <version>2.19.0-rc2</version>
      <version>2.10.0</version>
    </versions>
    <lastUpdated>20241128000000</lastUpdated>
  </versioning>
</metadata>`

// fakeMaven stands in for Maven Central for the length of one test.
func fakeMaven(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	old := mavenBase
	mavenBase = srv.URL
	t.Cleanup(func() { mavenBase = old; srv.Close() })
}

// latest_version for Maven: the request goes to the metadata file of the
// artifact on Maven Central, the XML is read, the versions come back in Maven
// order, and <release> wins over <latest> (which here is a release candidate).
func TestLatestVersionMaven(t *testing.T) {
	var asked string
	fakeMaven(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(jacksonMetadata))
	})
	params, _ := json.Marshal(map[string]string{"ecosystem": "gradle", "name": "com.fasterxml.jackson.core:jackson-databind"})
	out, err := (System{}).Execute(context.Background(), "latest_version", params, target.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "/maven2/com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml"; asked != want {
		t.Errorf("asked %q, want %q", asked, want)
	}
	info := out.(VersionInfo)
	if info.Ecosystem != EcosystemMaven || info.Latest != "2.18.2" {
		t.Errorf("info = %+v, want Maven / latest 2.18.2", info)
	}
	want := []string{"2.9.10.8", "2.10.0", "2.13.4.2", "2.18.2", "2.19.0-rc2"}
	if strings.Join(info.Versions, ",") != strings.Join(want, ",") {
		t.Errorf("versions = %v, want %v", info.Versions, want)
	}
	if len(info.Notes) != 0 {
		t.Errorf("notes = %v, want none", info.Notes)
	}
}

// Tomcat keeps three lines in one artifact; maven-metadata.xml names the one
// deployed last, which may be the oldest line.
func TestLatestVersionMavenReleaseIsNotTheHighest(t *testing.T) {
	fakeMaven(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<metadata><versioning>
		  <latest>9.0.98</latest><release>9.0.98</release>
		  <versions><version>10.1.34</version><version>11.0.0-M26</version>
		  <version>11.0.2</version><version>9.0.98</version></versions>
		</versioning></metadata>`))
	})
	info, err := fetchVersions(context.Background(), http.DefaultClient, EcosystemMaven, "org.apache.tomcat.embed:tomcat-embed-core")
	if err != nil {
		t.Fatal(err)
	}
	if info.Latest != "9.0.98" {
		t.Errorf("latest = %q — it is what the repository says, and stays so", info.Latest)
	}
	if len(info.Notes) != 1 || !strings.Contains(info.Notes[0], "11.0.2") {
		t.Errorf("notes = %v, want one naming 11.0.2 as higher", info.Notes)
	}
}

// A 404 is the common mistake (a typo, or an androidx artifact that lives on
// Google's repository). The error has to say which.
func TestLatestVersionMavenNotFound(t *testing.T) {
	fakeMaven(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	_, err := fetchVersions(context.Background(), http.DefaultClient, EcosystemMaven, "androidx.core:core-ktx")
	if err == nil {
		t.Fatal("expected an error for a 404")
	}
	for _, want := range []string{"androidx.core:core-ktx", "Maven Central"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must contain %q: %v", want, err)
		}
	}
}

// A malformed name is refused before a request goes out, and a broken answer
// is an error rather than an empty version list.
func TestLatestVersionMavenRefusesBadInput(t *testing.T) {
	fakeMaven(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "jackson-databind") {
			t.Errorf("a malformed name must not be fetched: %s", r.URL.Path)
		}
		w.Write([]byte("<html>proxy login</html>"))
	})
	if _, err := fetchVersions(context.Background(), http.DefaultClient, EcosystemMaven, "jackson-databind"); err == nil {
		t.Error("a name without a groupId must be refused")
	}
	if _, err := fetchVersions(context.Background(), http.DefaultClient, EcosystemMaven, "com.example:lib"); err == nil {
		t.Error("an answer that is not maven-metadata.xml must be an error")
	}
}

// fakeOSVMaven answers for one vulnerable Maven package, with two fix lines.
func fakeOSVMaven(t *testing.T, vulnerable string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			results := make([]map[string]any, len(body.Queries))
			for i, q := range body.Queries {
				if q.Package.Ecosystem != "Maven" {
					t.Errorf("ecosystem sent to OSV = %q, want Maven", q.Package.Ecosystem)
				}
				results[i] = map[string]any{"vulns": []any{}}
				if q.Package.Name == vulnerable {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "GHSA-jjjh-jjxp-wpff"}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/query":
			w.Write([]byte(`{"vulns":[{"id":"GHSA-jjjh-jjxp-wpff","aliases":["CVE-2022-42003"],
			  "summary":"Uncontrolled Resource Consumption in Jackson-databind",
			  "affected":[{"package":{"name":"` + vulnerable + `","ecosystem":"Maven"},
			  "database_specific":{"severity":"HIGH"},
			  "ranges":[{"type":"ECOSYSTEM","events":[
			    {"introduced":"0"},{"fixed":"2.12.7.1"},
			    {"introduced":"2.13.0"},{"fixed":"2.13.4.2"}]}]}]}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	old := osvBase
	osvBase = srv.URL
	t.Cleanup(func() { osvBase = old; srv.Close() })
}

const jackson = "com.fasterxml.jackson.core:jackson-databind"

// query_batch for Maven: the package goes to OSV as "Maven" with the
// groupId:artifactId name, and the finding carries the fix of the right line.
func TestQueryPackagesMaven(t *testing.T) {
	fakeOSVMaven(t, jackson)
	params := json.RawMessage(`{"packages":[
	  {"ecosystem":"kotlin","name":"org.jetbrains.kotlin:kotlin-stdlib","version":"2.1.0"},
	  {"ecosystem":"gradle","name":"` + jackson + `","version":"2.13.3"}]}`)
	out, err := (System{}).Execute(context.Background(), "query_batch", params, target.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(*BatchResult)
	if res.PackagesScanned != 2 || len(res.Findings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	f := res.Findings[0]
	if f.Package != jackson || f.Ecosystem != EcosystemMaven {
		t.Errorf("finding = %s/%s", f.Ecosystem, f.Package)
	}
	if f.Fixed != "2.13.4.2" || f.FixedCandidates != nil {
		t.Errorf("fixed = %q, candidates = %v — want 2.13.4.2 for the 2.13 line", f.Fixed, f.FixedCandidates)
	}
	if f.CVE != "CVE-2022-42003" || f.Severity != "HIGH" {
		t.Errorf("cve = %q, severity = %q", f.CVE, f.Severity)
	}
}

// scan_lockfile end to end on a gradle.lockfile in the checkout.
func TestScanGradleLockfile(t *testing.T) {
	fakeOSVMaven(t, jackson)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "repo", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := "# This is a Gradle generated file for dependency locking.\n" +
		jackson + ":2.13.3=compileClasspath,runtimeClasspath\n" +
		"org.junit.jupiter:junit-jupiter-api:5.10.0=testCompileClasspath,testRuntimeClasspath\n" +
		"empty=annotationProcessor\n"
	if err := os.WriteFile(filepath.Join(home, "repo", "app", "gradle.lockfile"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := target.WithWorkdir(context.Background(), home)
	out, err := (System{}).Execute(ctx, "scan_lockfile", json.RawMessage(`{"path":"repo/app/gradle.lockfile"}`), target.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(*ScanResult)
	if res.Ecosystem != EcosystemMaven || res.PackagesScanned != 2 {
		t.Errorf("ecosystem = %q, packages_scanned = %d — want Maven / 2", res.Ecosystem, res.PackagesScanned)
	}
	if len(res.Findings) != 1 || res.Findings[0].Fixed != "2.13.4.2" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Clean {
		t.Error("clean must be false")
	}
}

// The prompt doc is what tells an agent that Maven is covered at all.
func TestPromptDocCoversMaven(t *testing.T) {
	for _, want := range []string{"Maven", "gradle.lockfile", "repo1.maven.org", "gradlew dependencies"} {
		if !strings.Contains((System{}).PromptDoc(), want) {
			t.Errorf("the prompt doc must mention %q", want)
		}
	}
	d, _ := target.Describe("vulndb")
	if !strings.Contains(d.SetupDoc, "repo1.maven.org") {
		t.Error("the setup doc must name the Maven Central host for the egress allowlist")
	}
}
