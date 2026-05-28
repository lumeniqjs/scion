// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/api/idtoken"
)

const (
	testGCPAudience       = "https://scion-hub.lumeniq.ai"
	testAllowedSAEmail    = "mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com"
	testAllowedProjectID  = "3152156d-67ef-415f-8ca5-903b446e2894"
	testNotAllowedSAEmail = "someone-else@evil-project.iam.gserviceaccount.com"
)

// fakeOIDCValidator is an injectable OIDCValidator for tests. It returns the
// preconfigured payload/err and records the audience it was called with.
type fakeOIDCValidator struct {
	payload     *idtoken.Payload
	err         error
	gotAudience string
	calls       int
}

func (f *fakeOIDCValidator) Validate(_ context.Context, _ string, audience string) (*idtoken.Payload, error) {
	f.calls++
	f.gotAudience = audience
	if f.err != nil {
		return nil, f.err
	}
	return f.payload, nil
}

func testAllowlist() map[string]GCPIdentityGrant {
	return map[string]GCPIdentityGrant{
		testAllowedSAEmail: {
			ProjectID: testAllowedProjectID,
			Scopes:    []string{"agent:create", "agent:read", "agent:attach"},
		},
	}
}

func validGooglePayload(email string) *idtoken.Payload {
	return &idtoken.Payload{
		Issuer:   googleIssuerHTTPS,
		Audience: testGCPAudience,
		Subject:  "1234567890",
		Claims: map[string]interface{}{
			"email":          email,
			"email_verified": true,
			"iss":            googleIssuerHTTPS,
			"aud":            testGCPAudience,
		},
	}
}

func newTestService(t *testing.T, v OIDCValidator) *GCPIdentityService {
	t.Helper()
	svc, err := NewGCPIdentityService(testGCPAudience, testAllowlist(), v)
	if err != nil {
		t.Fatalf("NewGCPIdentityService returned error: %v", err)
	}
	return svc
}

func TestNewGCPIdentityService_RequiresAudience(t *testing.T) {
	if _, err := NewGCPIdentityService("", testAllowlist(), &fakeOIDCValidator{}); err == nil {
		t.Fatal("expected error for empty audience, got nil")
	}
	if _, err := NewGCPIdentityService("   ", testAllowlist(), &fakeOIDCValidator{}); err == nil {
		t.Fatal("expected error for whitespace-only audience, got nil")
	}
}

func TestGCPIdentityValidate_ValidAllowlistedSA(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc := newTestService(t, fake)

	identity, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if identity == nil {
		t.Fatal("expected scoped identity, got nil")
	}
	if got := identity.ScopedProjectID(); got != testAllowedProjectID {
		t.Errorf("project id = %q, want %q", got, testAllowedProjectID)
	}
	wantScopes := []string{"agent:create", "agent:read", "agent:attach"}
	for _, sc := range wantScopes {
		if !identity.HasScope(sc) {
			t.Errorf("expected scope %q to be present", sc)
		}
	}
	if identity.Email() != testAllowedSAEmail {
		t.Errorf("email = %q, want %q", identity.Email(), testAllowedSAEmail)
	}
	if identity.ID() != GCPIdentityUserID(testAllowedSAEmail) {
		t.Errorf("id = %q, want %q", identity.ID(), GCPIdentityUserID(testAllowedSAEmail))
	}
	// CRITICAL: the synthetic principal must never carry the admin role (the
	// authz layer admin-bypasses role=="admin").
	if identity.Role() == "admin" {
		t.Error("synthetic SA identity must NOT have admin role")
	}
	// The validator must have been called with the configured audience.
	if fake.gotAudience != testGCPAudience {
		t.Errorf("validator called with audience %q, want %q", fake.gotAudience, testGCPAudience)
	}
}

func TestGCPIdentityValidate_ScopesAreDefensivelyCopied(t *testing.T) {
	allow := testAllowlist()
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc, err := NewGCPIdentityService(testGCPAudience, allow, fake)
	if err != nil {
		t.Fatalf("NewGCPIdentityService: %v", err)
	}
	// Mutate the caller's allowlist scopes AFTER construction; the service must
	// have copied them so the authenticated identity is unaffected.
	allow[testAllowedSAEmail].Scopes[0] = "agent:manage"

	identity, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.HasScope("agent:manage") {
		t.Error("scope mutation leaked into authenticated identity; scopes were not copied")
	}
	if !identity.HasScope("agent:create") {
		t.Error("expected original agent:create scope to be retained")
	}
}

func TestGCPIdentityValidate_NonAllowlistedSA(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testNotAllowedSAEmail)}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil {
		t.Fatal("expected error for non-allowlisted SA, got nil")
	}
	if !errors.Is(err, ErrGCPIdentityNotAllowed) {
		t.Errorf("expected ErrGCPIdentityNotAllowed, got %v", err)
	}
}

func TestGCPIdentityValidate_WrongAudience_ValidatorRejects(t *testing.T) {
	// Models idtoken.Validate's own audience check rejecting the token.
	fake := &fakeOIDCValidator{err: errors.New("idtoken: audience provided does not match aud claim in the JWT")}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid, got %v", err)
	}
}

func TestGCPIdentityValidate_WrongAudience_DefenseInDepth(t *testing.T) {
	// Even if the validator somehow returned a payload with a mismatched
	// audience, our explicit re-check must reject it.
	p := validGooglePayload(testAllowedSAEmail)
	p.Audience = "https://some-other-relying-party.example"
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on audience mismatch, got %v", err)
	}
}

func TestGCPIdentityValidate_WrongIssuer(t *testing.T) {
	// idtoken.Validate does NOT verify the issuer, so a cryptographically valid
	// token from a non-Google issuer must be rejected here.
	p := validGooglePayload(testAllowedSAEmail)
	p.Issuer = "https://accounts.evil.example"
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on wrong issuer, got %v", err)
	}
}

func TestGCPIdentityValidate_BareGoogleIssuerAccepted(t *testing.T) {
	p := validGooglePayload(testAllowedSAEmail)
	p.Issuer = googleIssuerBare
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	if _, err := svc.ValidateToken(context.Background(), "header.payload.sig"); err != nil {
		t.Fatalf("expected bare google issuer to be accepted, got %v", err)
	}
}

func TestGCPIdentityValidate_Expired(t *testing.T) {
	fake := &fakeOIDCValidator{err: errors.New("idtoken: token expired: now=..., expires=...")}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on expired token, got %v", err)
	}
}

func TestGCPIdentityValidate_TamperedSignature(t *testing.T) {
	fake := &fakeOIDCValidator{err: errors.New("crypto/rsa: verification error")}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on tampered signature, got %v", err)
	}
}

func TestGCPIdentityValidate_Malformed(t *testing.T) {
	fake := &fakeOIDCValidator{err: errors.New("idtoken: invalid token, token must have three segments")}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "not-a-jwt")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on malformed token, got %v", err)
	}
}

func TestGCPIdentityValidate_EmptyTokenShortCircuits(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc := newTestService(t, fake)

	if _, err := svc.ValidateToken(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
	if _, err := svc.ValidateToken(context.Background(), "   "); err == nil {
		t.Fatal("expected error for whitespace token")
	}
	if fake.calls != 0 {
		t.Errorf("validator should not be called for empty token; calls=%d", fake.calls)
	}
}

func TestGCPIdentityValidate_MissingEmailClaim(t *testing.T) {
	p := &idtoken.Payload{
		Issuer:   googleIssuerHTTPS,
		Audience: testGCPAudience,
		Claims:   map[string]interface{}{"iss": googleIssuerHTTPS},
	}
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on missing email, got %v", err)
	}
}

func TestGCPIdentityValidate_EmailNotVerified(t *testing.T) {
	p := validGooglePayload(testAllowedSAEmail)
	p.Claims["email_verified"] = false
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	_, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err == nil || !errors.Is(err, ErrGCPIdentityInvalid) {
		t.Fatalf("expected ErrGCPIdentityInvalid on unverified email, got %v", err)
	}
}

func TestGCPIdentityValidate_EmailCaseInsensitive(t *testing.T) {
	// Token presents an upper-cased email; allowlist stores lower-case. Must match.
	p := validGooglePayload("MC-Cloud-Run-Invoker@Lumeniq-Saas-Factory.IAM.gserviceaccount.com")
	fake := &fakeOIDCValidator{payload: p}
	svc := newTestService(t, fake)

	identity, err := svc.ValidateToken(context.Background(), "header.payload.sig")
	if err != nil {
		t.Fatalf("expected case-insensitive email match, got %v", err)
	}
	if identity.ScopedProjectID() != testAllowedProjectID {
		t.Errorf("project id = %q, want %q", identity.ScopedProjectID(), testAllowedProjectID)
	}
}

func TestGCPIdentityValidate_MisconfiguredGrant(t *testing.T) {
	// A grant with no scopes can authorize nothing -> fail closed.
	allow := map[string]GCPIdentityGrant{
		testAllowedSAEmail: {ProjectID: testAllowedProjectID, Scopes: nil},
	}
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc, err := NewGCPIdentityService(testGCPAudience, allow, fake)
	if err != nil {
		t.Fatalf("NewGCPIdentityService: %v", err)
	}
	if _, err := svc.ValidateToken(context.Background(), "header.payload.sig"); err == nil {
		t.Fatal("expected error for grant with no scopes")
	}
}

func TestGCPIdentityValidate_NilServiceFailsClosed(t *testing.T) {
	var svc *GCPIdentityService
	if _, err := svc.ValidateToken(context.Background(), "header.payload.sig"); err == nil {
		t.Fatal("nil service must fail closed")
	}
}

func TestIsGoogleIssuer(t *testing.T) {
	cases := map[string]bool{
		googleIssuerHTTPS:               true,
		googleIssuerBare:                true,
		"https://accounts.evil.example": false,
		"scion-hub":                     false,
		"":                              false,
	}
	for iss, want := range cases {
		if got := isGoogleIssuer(iss); got != want {
			t.Errorf("isGoogleIssuer(%q) = %v, want %v", iss, got, want)
		}
	}
}

func TestPeekUnverifiedIssuer(t *testing.T) {
	token := makeUnsignedJWT(t, map[string]interface{}{
		"iss":   googleIssuerHTTPS,
		"aud":   testGCPAudience,
		"email": testAllowedSAEmail,
	})
	if got := peekUnverifiedIssuer(token); got != googleIssuerHTTPS {
		t.Errorf("peekUnverifiedIssuer = %q, want %q", got, googleIssuerHTTPS)
	}

	if got := peekUnverifiedIssuer("not-a-jwt"); got != "" {
		t.Errorf("peekUnverifiedIssuer(malformed) = %q, want empty", got)
	}
}

func TestClaimIsTrue(t *testing.T) {
	cases := []struct {
		v    interface{}
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"TRUE", true},
		{"false", false},
		{"", false},
		{1, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := claimIsTrue(c.v); got != c.want {
			t.Errorf("claimIsTrue(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestDefaultGCPIdentityAllowlist(t *testing.T) {
	allow := DefaultGCPIdentityAllowlist()
	grant, ok := allow[testAllowedSAEmail]
	if !ok {
		t.Fatalf("default allowlist missing %q", testAllowedSAEmail)
	}
	if grant.ProjectID != testAllowedProjectID {
		t.Errorf("project id = %q, want %q", grant.ProjectID, testAllowedProjectID)
	}
	if len(grant.Scopes) == 0 {
		t.Error("default grant must have scopes")
	}
}

// makeUnsignedJWT builds a syntactically valid (header.payload.sig) JWT whose
// payload encodes the given claims. The signature is bogus -- this is only for
// exercising unverified-parse helpers, never for authentication tests.
func makeUnsignedJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"test"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + sig
}

func TestGCPIdentityUserID_StableAndUUID(t *testing.T) {
	id1 := GCPIdentityUserID(" MC-Cloud-Run-Invoker@Lumeniq-Saas-Factory.IAM.GServiceAccount.com ")
	id2 := GCPIdentityUserID(testAllowedSAEmail)
	if id1 != id2 {
		t.Fatalf("GCPIdentityUserID is not stable/case-insensitive: %q != %q", id1, id2)
	}
	if _, err := uuid.Parse(id1); err != nil {
		t.Fatalf("GCPIdentityUserID = %q, want valid UUID: %v", id1, err)
	}
}
