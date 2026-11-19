package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
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

// latest_version for Maven: the request goes to the metadata file of the
// artifact on Maven Central, the XML is read, the versions come back in Maven
// order, and <release> wins over <latest> (which here is a release candidate).
func TestLatestVersionMaven(t *testing.T) {
	var asked string
	stubFetch(t, func(req covey.Request) covey.Response {
		asked = req.Path
		// The host hands a body that is not JSON over as Text.
		return covey.Response{Status: 200, Text: jacksonMetadata}
	})
	params, _ := json.Marshal(map[string]string{"ecosystem": "gradle", "name": "com.fasterxml.jackson.core:jackson-databind"})
	out, err := (plugin{}).Execute("latest_version", params)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml"; asked != want {
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
	// A release candidate above the release is no reason for a note.
	if len(info.Notes) != 0 {
		t.Errorf("notes = %v, want none", info.Notes)
	}
}

// Tomcat keeps three lines in one artifact; maven-metadata.xml names the one
// deployed last, which may be the oldest line. That must not pass as "latest"
// without a word.
func TestLatestVersionMavenReleaseIsNotTheHighest(t *testing.T) {
	stubFetch(t, func(covey.Request) covey.Response {
		return covey.Response{Status: 200, Text: `<metadata><versioning>
		  <latest>9.0.98</latest><release>9.0.98</release>
		  <versions><version>10.1.34</version><version>11.0.0-M26</version>
		  <version>11.0.2</version><version>9.0.98</version></versions>
		</versioning></metadata>`}
	})
	info, err := fetchVersions(EcosystemMaven, "org.apache.tomcat.embed:tomcat-embed-core")
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
// Google's repository). The error has to say which, not "not known to this
// source".
func TestLatestVersionMavenNotFound(t *testing.T) {
	stubFetch(t, func(covey.Request) covey.Response {
		return covey.Response{Status: 404, Text: "<html>404 Not Found</html>"}
	})
	_, err := fetchVersions(EcosystemMaven, "androidx.core:core-ktx")
	if err == nil {
		t.Fatal("expected an error for a 404")
	}
	for _, want := range []string{"androidx.core:core-ktx", "Maven Central", "repo1.maven.org"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must contain %q: %v", want, err)
		}
	}
}

// A malformed name is refused before anything leaves the module, and a
// broken answer is an error rather than an empty version list.
func TestLatestVersionMavenRefusesBadInput(t *testing.T) {
	stubFetch(t, func(req covey.Request) covey.Response {
		if strings.Contains(req.Path, "jackson-databind") {
			t.Errorf("a malformed name must not be fetched: %s", req.Path)
		}
		return covey.Response{Status: 200, Text: "<html>proxy login</html>"}
	})
	if _, err := fetchVersions(EcosystemMaven, "jackson-databind"); err == nil {
		t.Error("a name without a groupId must be refused")
	}
	if _, err := fetchVersions(EcosystemMaven, "com.example:lib"); err == nil {
		t.Error("an answer that is not maven-metadata.xml must be an error")
	}
}

// query_batch for Maven: the package goes to OSV with OSV's ecosystem name and
// the groupId:artifactId name, and the finding carries the fix of the right
// line.
func TestQueryPackagesMaven(t *testing.T) {
	const name = "com.fasterxml.jackson.core:jackson-databind"
	stubFetch(t, func(req covey.Request) covey.Response {
		var body struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		switch {
		case strings.HasSuffix(req.Path, "/v1/querybatch"):
			json.Unmarshal(req.Body, &body)
			out := `{"results":[`
			for i, q := range body.Queries {
				if q.Package.Ecosystem != "Maven" {
					t.Errorf("ecosystem sent to OSV = %q, want Maven", q.Package.Ecosystem)
				}
				if i > 0 {
					out += ","
				}
				if q.Package.Name == name {
					out += `{"vulns":[{"id":"GHSA-jjjh-jjxp-wpff"}]}`
				} else {
					out += `{"vulns":[]}`
				}
			}
			return jsonResp(out + `]}`)
		case strings.HasSuffix(req.Path, "/v1/query"):
			return jsonResp(`{"vulns":[{"id":"GHSA-jjjh-jjxp-wpff","aliases":["CVE-2022-42003"],
			  "summary":"Uncontrolled Resource Consumption in Jackson-databind",
			  "affected":[{"package":{"name":"` + name + `","ecosystem":"Maven"},
			  "database_specific":{"severity":"HIGH"},
			  "ranges":[{"type":"ECOSYSTEM","events":[
			    {"introduced":"0"},{"fixed":"2.12.7.1"},
			    {"introduced":"2.13.0"},{"fixed":"2.13.4.2"}]}]}]}]}`)
		default:
			t.Errorf("unexpected path %s", req.Path)
			return covey.Response{Status: 404}
		}
	})

	params := json.RawMessage(`{"packages":[
	  {"ecosystem":"kotlin","name":"org.jetbrains.kotlin:kotlin-stdlib","version":"2.1.0"},
	  {"ecosystem":"gradle","name":"` + name + `","version":"2.13.3"}]}`)
	out, err := (plugin{}).Execute("query_batch", params)
	if err != nil {
		t.Fatal(err)
	}
	res := out.(*BatchResult)
	if res.PackagesScanned != 2 || len(res.Findings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	f := res.Findings[0]
	if f.Package != name || f.Ecosystem != EcosystemMaven {
		t.Errorf("finding = %s/%s", f.Ecosystem, f.Package)
	}
	if f.Fixed != "2.13.4.2" || f.FixedCandidates != nil {
		t.Errorf("fixed = %q, candidates = %v — want 2.13.4.2 for the 2.13 line", f.Fixed, f.FixedCandidates)
	}
	if f.CVE != "CVE-2022-42003" || f.Severity != "HIGH" {
		t.Errorf("cve = %q, severity = %q", f.CVE, f.Severity)
	}
}

// The Maven host is declared: without it in Hosts the host refuses every
// latest_version call for Maven before it reaches the egress proxy.
func TestDescribeDeclaresMavenCentral(t *testing.T) {
	d := (plugin{}).Describe()
	found := false
	for _, h := range d.Hosts {
		if h == "repo1.maven.org" {
			found = true
		}
	}
	if !found {
		t.Errorf("repo1.maven.org is not declared: %v", d.Hosts)
	}
	for _, want := range []string{"Maven", "gradle.lockfile", "repo1.maven.org", "gradlew dependencies"} {
		if !strings.Contains(promptDoc, want) {
			t.Errorf("the prompt doc must mention %q", want)
		}
	}
}
