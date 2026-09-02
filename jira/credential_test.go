package jira

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

func TestInspectOnCloudIsProbeWithEmptyHands(t *testing.T) {
	f := newFakeJira(t, true)
	info, err := System{}.Inspect(context.Background(), f.cred())
	if err != nil {
		t.Fatal(err)
	}
	if info.Identity == "" || info.ExpiresAt != nil || info.Rotatable || info.ID != "" {
		t.Fatalf("cloud info = %+v — Atlassian says nothing about a Cloud token's lifetime", info)
	}
	if _, _, err := (System{}).Rotate(context.Background(), f.cred()); err == nil {
		t.Fatal("a Cloud token cannot be rotated through the API — Rotate has to say so")
	}
}

func TestInspectNamesTheTokenOnlyWhenItIsUnambiguous(t *testing.T) {
	f := newFakeJira(t, false)
	ctx := context.Background()

	f.pats = []map[string]any{{"id": 7, "name": "hand-made", "expiringAt": "2026-12-01T08:00:00.000+0000"}}
	info, err := System{}.Inspect(ctx, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Rotatable || info.ID != "7" || info.ExpiresAt == nil {
		t.Fatalf("a single token is the caller's: %+v", info)
	}
	if want := time.Date(2026, 12, 1, 8, 0, 0, 0, time.UTC); !info.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %s, want %s", info.ExpiresAt, want)
	}

	f.pats = append(f.pats, map[string]any{"id": 8, "name": "covey-20260901T000000Z", "expiringAt": "2027-09-01T00:00:00.000+0000"})
	info, _ = System{}.Inspect(ctx, f.cred())
	if info.ID != "8" {
		t.Fatalf("among several, the one covey minted is the caller's: %+v", info)
	}

	f.pats = append(f.pats, map[string]any{"id": 9, "name": "covey-20260902T000000Z", "expiringAt": nil})
	info, _ = System{}.Inspect(ctx, f.cred())
	if info.ID != "" || info.ExpiresAt != nil || !info.Rotatable {
		t.Fatalf("two minted tokens cannot be told apart — no guess: %+v", info)
	}
}

func TestInspectSurvivesAnInstanceWithoutThePATAPI(t *testing.T) {
	f := newFakeJira(t, false)
	f.noPATAPI = true
	info, err := System{}.Inspect(context.Background(), f.cred())
	if err != nil || info.Identity == "" {
		t.Fatalf("Probe still answers: %+v, %v", info, err)
	}
}

func TestRotateMintsASuccessorAndRevokeDeletesById(t *testing.T) {
	f := newFakeJira(t, false)
	ctx := context.Background()
	old := f.cred("project=\"ACME\"")

	next, info, err := System{}.Rotate(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if next.Token != "minted-100" || next.BaseURL != old.BaseURL {
		t.Fatalf("successor = %+v — a new token under the same assignment", next)
	}
	if info.ID != "100" || info.ExpiresAt == nil || !info.Rotatable {
		t.Fatalf("info = %+v", info)
	}
	if c, _ := NewClient(next); len(c.Config().Projects) != 1 || c.Config().Projects[0] != "ACME" {
		t.Fatal("the project wall travels with the base URL, not with the token")
	}
	if err := (System{}).Revoke(ctx, next, "7"); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "7" {
		t.Fatalf("revoked = %v", f.revoked)
	}
	if err := (System{}).Revoke(ctx, next, ""); err != nil || len(f.revoked) != 1 {
		t.Fatal("without an id there is nothing to revoke — and that is not an error")
	}
}

func TestA401IsTheCredentialNotTheRequest(t *testing.T) {
	f := newFakeJira(t, false)
	f.reject401 = true
	_, err := f.client(t).GetIssue(context.Background(), "ACME-17")
	if !target.IsCredentialRejected(err) {
		t.Fatalf("a 401 has to be marked as a rejected credential, got %v", err)
	}
	var api *apiError
	if !errors.As(err, &api) || api.Status() != 401 {
		t.Fatal("what Jira said still travels underneath")
	}
	if _, err := (System{}).Probe(context.Background(), f.cred()); !target.IsCredentialRejected(err) {
		t.Fatalf("Probe: %v", err)
	}
}

func TestParsePATTimeReadsJirasZone(t *testing.T) {
	for _, in := range []string{"2026-12-01T08:00:00.000+0000", "2026-12-01T08:00:00+0000", "2026-12-01T08:00:00Z", "2026-12-01T09:00:00+01:00"} {
		got := parsePATTime(in)
		if got == nil || !got.Equal(time.Date(2026, 12, 1, 8, 0, 0, 0, time.UTC)) {
			t.Errorf("%s → %v", in, got)
		}
	}
	if parsePATTime("") != nil || parsePATTime("never") != nil {
		t.Error("nothing or nonsense reads as no expiry")
	}
}
