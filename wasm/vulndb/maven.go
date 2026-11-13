package main

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Maven: the ecosystem of Java and Kotlin, and of every Gradle build. OSV
// names it "Maven" and a package "groupId:artifactId"
// (com.fasterxml.jackson.core:jackson-databind). Three things are different
// enough from npm, Packagist and Pub to live in a file of their own: the
// version ordering, the registry (maven-metadata.xml, not JSON), and Gradle's
// lock file, which is parsed in lockfile.go.

// --- Versions ---

// Maven versions are not semver-shaped: "1.0.0.Final", "33.4.0-jre",
// "5.3.0.CR2", "2.0.0.RELEASE". Read as semver, "-jre" would rank as a
// pre-release BELOW 33.4.0, and "1.0.0.Final" would not parse at all. So Maven
// gets its own comparison, modelled on Maven's ComparableVersion for the shape
// nearly every artifact on Central has: a numeric core and at most one
// qualifier, optionally numbered.
//
// Anything outside that shape (a numeric qualifier like "1.0-1", a timestamped
// snapshot, two qualifiers like "1.0-jre-SNAPSHOT") is reported as not
// comparable. So is an unknown qualifier on an equal core ("32.0.0-jre" against
// "32.0.0-android"): Maven orders those lexically, which is a rule, not a
// meaning, and a fix version derived from it would be a guess. The caller then
// names every candidate instead.

// Maven's qualifier order: alpha < beta < milestone < rc = cr < snapshot <
// release (= "" = final = ga) < sp < anything unknown.
const (
	mavenAlpha = iota
	mavenBeta
	mavenMilestone
	mavenRC
	mavenSnapshot
	mavenRelease
	mavenSP
	mavenUnknown
)

// mavenVersion is a parsed Maven version.
type mavenVersion struct {
	core []int
	rank int
	// word is the qualifier as written (lower case). Only compared for
	// unknown qualifiers, where it is the whole identity.
	word string
	// number is the qualifier's number: rc2 → 2. Zero when absent.
	number int
}

// parseMavenVersion reads "<n>(.<n>)*" optionally followed by one qualifier,
// separated by ".", "-" or nothing ("1.0RC1"), and an optional number after
// the qualifier ("rc1", "rc-1", "beta.3"). ok=false for everything else.
func parseMavenVersion(v string) (mv mavenVersion, ok bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return mavenVersion{}, false
	}

	i := 0
	for {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == i {
			return mavenVersion{}, false // empty segment, or a version that starts with a letter
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return mavenVersion{}, false
		}
		mv.core = append(mv.core, n)
		i = j
		if i == len(s) {
			mv.rank = mavenRelease
			return mv, true
		}
		if s[i] == '.' && i+1 < len(s) && isDigit(s[i+1]) {
			i++
			continue
		}
		break
	}

	rest := s[i:]
	if rest[0] == '.' || rest[0] == '-' {
		rest = rest[1:]
	}
	k := 0
	for k < len(rest) && rest[k] >= 'a' && rest[k] <= 'z' {
		k++
	}
	word, tail := rest[:k], rest[k:]
	if word == "" {
		// "1.0-1", "1.0-20240101.120000-3": Maven nests a numeric qualifier
		// as a sub-list. Not modelled, so not ranked.
		return mavenVersion{}, false
	}
	numbered := false
	if tail != "" {
		if tail[0] == '.' || tail[0] == '-' {
			tail = tail[1:]
		}
		if tail == "" || strings.TrimLeft(tail, "0123456789") != "" {
			return mavenVersion{}, false // a second qualifier, or trailing junk
		}
		n, err := strconv.Atoi(tail)
		if err != nil {
			return mavenVersion{}, false
		}
		mv.number, numbered = n, true
	}

	mv.word = word
	switch word {
	case "alpha":
		mv.rank = mavenAlpha
	case "beta":
		mv.rank = mavenBeta
	case "milestone":
		mv.rank = mavenMilestone
	case "rc", "cr":
		mv.rank = mavenRC
	case "snapshot":
		mv.rank = mavenSnapshot
	case "final", "ga", "release":
		if numbered {
			return mavenVersion{}, false // "1.0.Final2" has no meaning Maven defines
		}
		mv.rank = mavenRelease
	case "sp":
		mv.rank = mavenSP
	// Maven reads a, b and m as alpha, beta and milestone only when a number
	// follows ("1.0b2"); on their own they are ordinary unknown words.
	case "a", "b", "m":
		mv.rank = mavenUnknown
		if numbered {
			mv.rank = map[string]int{"a": mavenAlpha, "b": mavenBeta, "m": mavenMilestone}[word]
		}
	default:
		mv.rank = mavenUnknown
	}
	return mv, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareMaven compares two Maven versions. ok=false means at least one of
// them is outside the modelled shape, or the order would hinge on two
// different unknown qualifiers.
func compareMaven(a, b string) (cmp int, ok bool) {
	va, oka := parseMavenVersion(a)
	vb, okb := parseMavenVersion(b)
	if !oka || !okb {
		return 0, false
	}
	// The core decides first: missing segments count as 0 ("1.0" == "1.0.0"),
	// and a qualifier never outweighs a higher number in the core — in Maven
	// too, 1.0.0-jre < 1.0.1 and 1.0.0.Final < 1.0.0.1.
	n := max(len(va.core), len(vb.core))
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(va.core) {
			x = va.core[i]
		}
		if i < len(vb.core) {
			y = vb.core[i]
		}
		if x != y {
			return sign(x - y), true
		}
	}
	if va.rank == mavenUnknown || vb.rank == mavenUnknown {
		if va.rank != vb.rank || va.word != vb.word {
			return 0, false
		}
	}
	if va.rank != vb.rank {
		return sign(va.rank - vb.rank), true
	}
	return sign(va.number - vb.number), true
}

func sign(d int) int {
	switch {
	case d < 0:
		return -1
	case d > 0:
		return 1
	}
	return 0
}

// --- Registry ---

// mavenMetadataPath turns groupId:artifactId into the path of the artifact's
// maven-metadata.xml below /maven2/. The characters are checked rather than
// escaped: Maven coordinates are [A-Za-z0-9_.-], and a name with anything
// else in it ("../", "?") is not a package but a different request.
func mavenMetadataPath(name string) (string, error) {
	invalid := fmt.Errorf("maven packages are named groupId:artifactId, e.g. com.fasterxml.jackson.core:jackson-databind — %q is not one (a version goes into \"version\", not into the name)", name)
	group, artifact, ok := strings.Cut(strings.TrimSpace(name), ":")
	if !ok || strings.Contains(artifact, ":") {
		return "", invalid
	}
	segments := strings.Split(group, ".")
	for _, s := range segments {
		if !validMavenID(s, false) {
			return "", invalid
		}
	}
	if !validMavenID(artifact, true) {
		return "", invalid
	}
	return strings.Join(segments, "/") + "/" + artifact + "/maven-metadata.xml", nil
}

func validMavenID(s string, dots bool) bool {
	if s == "" || s[0] == '.' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		case c == '.' && dots:
		default:
			return false
		}
	}
	return true
}

// mavenMetadata is maven-metadata.xml, reduced to the version list.
type mavenMetadata struct {
	XMLName    xml.Name `xml:"metadata"`
	Versioning struct {
		Latest   string   `xml:"latest"`
		Release  string   `xml:"release"`
		Versions []string `xml:"versions>version"`
	} `xml:"versioning"`
}

// parseMavenMetadata reads the version list and the release the repository
// names. <release> is preferred over <latest>: latest may be a snapshot.
func parseMavenMetadata(data []byte) (latest string, versions []string, err error) {
	var md mavenMetadata
	if err := xml.Unmarshal(data, &md); err != nil {
		return "", nil, fmt.Errorf("maven-metadata.xml is not readable: %w", err)
	}
	for _, v := range md.Versioning.Versions {
		if v = strings.TrimSpace(v); v != "" {
			versions = append(versions, v)
		}
	}
	latest = strings.TrimSpace(md.Versioning.Release)
	if latest == "" {
		latest = strings.TrimSpace(md.Versioning.Latest)
	}
	if latest == "" && len(versions) == 0 {
		return "", nil, fmt.Errorf("maven-metadata.xml lists no versions")
	}
	return latest, versions, nil
}

// mavenReleaseNote warns when <release> is not the highest version.
// maven-metadata.xml names the most recently DEPLOYED release, and a project
// that maintains several lines in one artifact (Tomcat 9, 10 and 11 in
// tomcat-embed-core) deploys a 9.0.x after an 11.0.x. sorted must be in
// ascending order. Pre-releases and snapshots above the release are no reason
// for a note: they are not what anyone upgrades to for a fix.
func mavenReleaseNote(release string, sorted []string) string {
	if release == "" {
		return ""
	}
	for i := len(sorted) - 1; i >= 0; i-- {
		v, ok := parseMavenVersion(sorted[i])
		if !ok || v.rank < mavenRelease {
			continue
		}
		if c, ok := compareMaven(sorted[i], release); ok && c > 0 {
			return fmt.Sprintf("maven-metadata.xml names %s as the release — that is the most recently deployed one, not the highest (%s is higher). Pick the fix version from the line the project is on", release, sorted[i])
		}
		return ""
	}
	return ""
}

// mavenNotFound is the error for a 404 on maven-metadata.xml: the coordinates
// are wrong, or the artifact lives in a repository other than Maven Central.
func mavenNotFound(name string) error {
	host := mavenBase
	if u, err := url.Parse(mavenBase); err == nil && u.Host != "" {
		host = u.Host
	}
	return fmt.Errorf("%s is not on Maven Central (%s has no maven-metadata.xml for it) — check the groupId:artifactId spelling. Artifacts published only to another repository (Google's Maven repository for androidx.* and com.android.*, JitPack, a company Nexus) are not looked up", name, host)
}
