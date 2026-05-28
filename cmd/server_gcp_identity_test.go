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

package cmd

import (
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/hub"
)

func TestResolveGCPIdentityAuth_DisabledByDefault(t *testing.T) {
	t.Setenv("SCION_SERVER_GCP_IDENTITY_ENABLED", "")
	t.Setenv("SCION_SERVER_GCP_IDENTITY_AUDIENCE", "")

	audience, allowlist := resolveGCPIdentityAuth()
	if audience != "" {
		t.Errorf("expected empty audience when disabled, got %q", audience)
	}
	if allowlist != nil {
		t.Errorf("expected nil allowlist when disabled, got %v", allowlist)
	}
}

func TestResolveGCPIdentityAuth_NonTrueValuesStayOff(t *testing.T) {
	for _, v := range []string{"false", "1", "yes", "TRUEish", " "} {
		t.Setenv("SCION_SERVER_GCP_IDENTITY_ENABLED", v)
		audience, allowlist := resolveGCPIdentityAuth()
		if audience != "" || allowlist != nil {
			t.Errorf("value %q must NOT enable the feature; got audience=%q allowlist=%v", v, audience, allowlist)
		}
	}
}

func TestResolveGCPIdentityAuth_EnabledDefaults(t *testing.T) {
	t.Setenv("SCION_SERVER_GCP_IDENTITY_ENABLED", "true")
	t.Setenv("SCION_SERVER_GCP_IDENTITY_AUDIENCE", "")

	audience, allowlist := resolveGCPIdentityAuth()
	if audience != hub.GCPIdentityDefaultAudience {
		t.Errorf("audience = %q, want default %q", audience, hub.GCPIdentityDefaultAudience)
	}
	if len(allowlist) == 0 {
		t.Fatal("expected seeded allowlist when enabled")
	}
	const mcSA = "mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com"
	grant, ok := allowlist[mcSA]
	if !ok {
		t.Fatalf("allowlist missing seeded SA %q", mcSA)
	}
	if grant.ProjectID == "" || len(grant.Scopes) == 0 {
		t.Errorf("seeded grant must have project + scopes, got %+v", grant)
	}
}

func TestResolveGCPIdentityAuth_EnabledCaseInsensitiveWithOverride(t *testing.T) {
	t.Setenv("SCION_SERVER_GCP_IDENTITY_ENABLED", "TRUE")
	t.Setenv("SCION_SERVER_GCP_IDENTITY_AUDIENCE", "https://custom-hub.example")

	audience, allowlist := resolveGCPIdentityAuth()
	if audience != "https://custom-hub.example" {
		t.Errorf("audience override not applied, got %q", audience)
	}
	if len(allowlist) == 0 {
		t.Error("expected seeded allowlist when enabled")
	}
}
