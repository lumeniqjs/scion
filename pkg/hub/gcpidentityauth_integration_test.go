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
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGCPIdentity_EndToEnd_ReachesProtectedHandler exercises the full inbound
// path: a Google-issued OIDC token for the allowlisted SA passes through
// UnifiedAuthMiddleware -> RequireUserAuth and reaches a protected handler with
// the correct project scope and scopes available on the identity.
func TestGCPIdentity_EndToEnd_ReachesProtectedHandler(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc, err := NewGCPIdentityService(testGCPAudience, testAllowlist(), fake)
	if err != nil {
		t.Fatalf("NewGCPIdentityService: %v", err)
	}
	cfg := AuthConfig{Mode: "production", GCPIdentitySvc: svc}

	var sawScoped *ScopedUserIdentity
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scoped, ok := GetUserIdentityFromContext(r.Context()).(*ScopedUserIdentity); ok {
			sawScoped = scoped
		}
		w.WriteHeader(http.StatusOK)
	})
	// Compose the same way the server does: unified auth then RequireUserAuth.
	handler := UnifiedAuthMiddleware(cfg)(RequireUserAuth(protected))

	token := makeUnsignedJWT(t, map[string]interface{}{
		"iss":   googleIssuerHTTPS,
		"aud":   testGCPAudience,
		"email": testAllowedSAEmail,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 reaching protected handler, got %d: %s", rec.Code, rec.Body.String())
	}
	if sawScoped == nil {
		t.Fatal("protected handler did not see a *ScopedUserIdentity")
	}
	if sawScoped.ScopedProjectID() != testAllowedProjectID {
		t.Errorf("scoped project = %q, want %q", sawScoped.ScopedProjectID(), testAllowedProjectID)
	}
	if !sawScoped.HasScope("agent:dispatch") {
		t.Error("expected agent:dispatch scope on the identity")
	}
	if sawScoped.Role() == "admin" {
		t.Error("GCP SA identity must NOT carry the admin role")
	}
}

// TestGCPIdentity_AuthzScopingMatchesUAT proves the GCP-minted ScopedUserIdentity
// is enforced by the authz layer identically to a UAT: in-project + in-scope
// requests proceed past the UAT constraint gate, while wrong-project or
// out-of-scope requests are denied.
func TestGCPIdentity_AuthzScopingMatchesUAT(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	svc, err := NewGCPIdentityService(testGCPAudience, testAllowlist(), fake)
	if err != nil {
		t.Fatalf("NewGCPIdentityService: %v", err)
	}
	identity, err := svc.ValidateToken(t.Context(), "header.payload.sig")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	// enforceUATConstraints is store-free, so a bare AuthzService is sufficient.
	az := &AuthzService{}

	t.Run("in-project in-scope proceeds", func(t *testing.T) {
		res := Resource{Type: "agent", ID: "agent-1", ParentType: "project", ParentID: testAllowedProjectID}
		if denied := az.enforceUATConstraints(identity, res, ActionDispatch); denied != nil {
			t.Errorf("expected constraint to allow proceed, got deny: %s", denied.Reason)
		}
	})

	t.Run("wrong project denied", func(t *testing.T) {
		res := Resource{Type: "agent", ID: "agent-1", ParentType: "project", ParentID: "some-other-project"}
		denied := az.enforceUATConstraints(identity, res, ActionDispatch)
		if denied == nil || denied.Allowed {
			t.Error("expected deny for resource in a different project")
		}
	})

	t.Run("out-of-scope action denied", func(t *testing.T) {
		// agent:delete is NOT in the seeded grant's scopes.
		res := Resource{Type: "agent", ID: "agent-1", ParentType: "project", ParentID: testAllowedProjectID}
		denied := az.enforceUATConstraints(identity, res, ActionDelete)
		if denied == nil || denied.Allowed {
			t.Error("expected deny for action outside the token scopes")
		}
	})
}
