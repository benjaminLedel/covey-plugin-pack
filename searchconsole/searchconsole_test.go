package searchconsole

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// schluessel builds a service-account key file with a fresh RSA key, so the
// tests exercise the real signing path instead of a stub.
func schluessel(t *testing.T, tokenURI string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509PKCS8(t, key),
	})
	roh, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "covey-seo@beispiel.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
		"token_uri":    tokenURI,
	})
	return string(roh)
}

func x509PKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Der haeufigste Fehler beim Einrichten, mit Abstand: jemand fuegt einen
// API-Schluessel ein statt der Schluesseldatei. Die Meldung muss das sagen,
// nicht "invalid character".
func TestNewClientSagtWasFalschIst(t *testing.T) {
	faelle := map[string]struct{ token, erwartet string }{
		"leer":                {"", "searchconsole_token is missing"},
		"API-Schlüssel":       {"AIzaSyD-nichts-davon-ist-JSON", "not a service-account JSON key"},
		"JSON ohne Schlüssel": {`{"type":"service_account"}`, "client_email or private_key missing"},
	}
	for name, f := range faelle {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient(target.Credential{Token: f.token})
			if err == nil {
				t.Fatal("wurde angenommen")
			}
			if !strings.Contains(err.Error(), f.erwartet) {
				t.Fatalf("Meldung nennt das Problem nicht:\n  ist:      %v\n  erwartet: %s", err, f.erwartet)
			}
		})
	}
}

// Der ganze Weg: JWT signieren, gegen den Token-Endpunkt tauschen, damit die
// API rufen. Gegen einen Server, der die Behauptung nachprueft.
func TestZugangUndAbruf(t *testing.T) {
	var gesehen struct{ grant, assertion, auth string }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			gesehen.grant = r.Form.Get("grant_type")
			gesehen.assertion = r.Form.Get("assertion")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"ya29.test","expires_in":3600}`))
		case "/webmasters/v3/sites":
			gesehen.auth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"siteEntry":[{"siteUrl":"sc-domain:beispiel.de","permissionLevel":"siteOwner"}]}`))
		default:
			t.Errorf("unerwarteter Pfad %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c, err := NewClient(target.Credential{
		Token:   schluessel(t, srv.URL+"/token"),
		BaseURL: "sc-domain:beispiel.de",
	})
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	c.basis = srv.URL

	roh, err := c.listSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := roh.(map[string]any)
	seiten := m["sites"].([]Seite)
	if len(seiten) != 1 || seiten[0].SiteURL != "sc-domain:beispiel.de" {
		t.Fatalf("Antwort unerwartet: %+v", seiten)
	}

	if gesehen.grant != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("falscher grant_type: %q", gesehen.grant)
	}
	if strings.Count(gesehen.assertion, ".") != 2 {
		t.Fatalf("assertion ist kein JWT: %q", gesehen.assertion)
	}
	if gesehen.auth != "Bearer ya29.test" {
		t.Fatalf("Token nicht mitgeschickt: %q", gesehen.auth)
	}

	// Zweiter Aufruf: kein neuer Token. Ein Audit-Lauf mit zwanzig Abrufen
	// soll sich nicht zwanzigmal anmelden.
	gesehen.assertion = ""
	if _, err := c.listSites(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gesehen.assertion != "" {
		t.Fatal("Token wurde ein zweites Mal geholt, obwohl er noch gilt")
	}
}

// Eine leere Liste ist Googles Art zu sagen "das Dienstkonto ist Nutzer von
// gar nichts". Wer das als "noch keine Daten" liest, sucht eine Stunde an der
// falschen Stelle.
func TestLeereListeErklaertSich(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, _ := NewClient(target.Credential{Token: schluessel(t, srv.URL+"/token")})
	c.HTTP = srv.Client()
	c.basis = srv.URL

	roh, err := c.listSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hinweis, _ := roh.(map[string]any)["hinweis"].(string)
	if !strings.Contains(hinweis, "not a user of any property") {
		t.Fatalf("kein erklaerender Hinweis: %q", hinweis)
	}
}

// Ein abgelehnter Schluessel ist ein Zugangsdaten-Fehler, kein Aktionsfehler.
// Der Host markiert daraufhin das Secret, statt den Fehlschlag unter der
// Aktion abzulegen, wo er drei Wochen spaeter wie ein Rechteproblem aussieht.
func TestAbgelehnterSchluesselIstZugangsfehler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	c, _ := NewClient(target.Credential{Token: schluessel(t, srv.URL+"/token")})
	c.HTTP = srv.Client()
	if _, err := c.accessToken(context.Background()); !target.IsCredentialRejected(err) {
		t.Fatalf("nicht als Zugangsdaten-Fehler erkannt: %v", err)
	}
}

// 403 heisst hier fast immer dasselbe, und das gehoert ausgesprochen: Der
// Schluessel stimmt, aber niemand hat das Dienstkonto der Property zugeordnet.
func TestVerbotNenntDenVergessenenSchritt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"message":"User does not have sufficient permission"}}`))
	}))
	defer srv.Close()

	c, _ := NewClient(target.Credential{Token: schluessel(t, srv.URL+"/token"), BaseURL: "sc-domain:beispiel.de"})
	c.HTTP = srv.Client()
	c.basis = srv.URL

	_, err := c.listSites(context.Background())
	if err == nil || !strings.Contains(err.Error(), "a user of the property") {
		t.Fatalf("Meldung erklaert den fehlenden Schritt nicht: %v", err)
	}
	if !strings.Contains(err.Error(), "covey-seo@beispiel.iam.gserviceaccount.com") {
		t.Fatalf("Meldung nennt die Adresse nicht, die eingetragen werden muss: %v", err)
	}
}

// Das Fenster endet drei Tage in der Vergangenheit, nicht heute: Search
// Console haelt Daten so lange zurueck, und ein Fenster bis heute sieht immer
// nach Einbruch aus.
func TestZeitraumEndetVorDerLuecke(t *testing.T) {
	von, bis := Eingabe{}.zeitraum()
	ende, _ := time.Parse("2006-01-02", bis)
	if tage := int(time.Since(ende).Hours() / 24); tage < 2 || tage > 4 {
		t.Fatalf("Ende liegt %d Tage zurueck, erwartet ~3: %s", tage, bis)
	}
	start, _ := time.Parse("2006-01-02", von)
	if spanne := int(ende.Sub(start).Hours() / 24); spanne != 28 {
		t.Fatalf("Standardfenster ist %d Tage, erwartet 28", spanne)
	}

	// Ausdrueckliche Daten gewinnen.
	von, bis = Eingabe{StartDate: "2026-01-01", EndDate: "2026-01-31"}.zeitraum()
	if von != "2026-01-01" || bis != "2026-01-31" {
		t.Fatalf("ausdrueckliche Daten uebergangen: %s..%s", von, bis)
	}
}

// Jede Aktion bekommt ein eigenes Subjekt: Ein Guard-Rail, das nur
// "searchconsole" sagen kann, kann nur das ganze System verbieten — und
// inspect_url mit seinem Tageskontingent verdient eine eigene Schranke.
func TestActionSubjectTrenntDieAktionen(t *testing.T) {
	s := System{}
	if got := s.ActionSubject("inspect_url", nil); got != "searchconsole:inspect_url" {
		t.Fatalf("%q", got)
	}
	if s.ActionSubject("list_sites", nil) == s.ActionSubject("inspect_url", nil) {
		t.Fatal("Aktionen sind nicht unterscheidbar")
	}
}

func TestUnbekannteAktion(t *testing.T) {
	_, err := System{}.Execute(context.Background(), "loeschen", nil,
		target.Credential{Token: schluessel(t, "https://example.invalid/token")})
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("unbekannte Aktion nicht abgewiesen: %v", err)
	}
}
