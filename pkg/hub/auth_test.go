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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/apiclient"
	"github.com/GoogleCloudPlatform/scion/pkg/util/logging"
)

func TestUnifiedAuthMiddleware_DevToken(t *testing.T) {
	devToken := "scion_dev_test_token_12345678901234567890123456789012"

	cfg := AuthConfig{
		Mode:           "development",
		DevAuthEnabled: true,
		DevAuthToken:   devToken,
		Debug:          false,
	}

	middleware := UnifiedAuthMiddleware(cfg)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectIdentity bool
	}{
		{
			name:           "valid dev token",
			authHeader:     "Bearer " + devToken,
			expectedStatus: http.StatusOK,
			expectIdentity: true,
		},
		{
			name:           "invalid dev token",
			authHeader:     "Bearer scion_dev_wrong_token_12345678901234567890",
			expectedStatus: http.StatusUnauthorized,
			expectIdentity: false,
		},
		{
			name:           "missing auth header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectIdentity: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotIdentity Identity

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotIdentity = GetIdentityFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}

			if tc.expectIdentity && gotIdentity == nil {
				t.Error("expected identity in context, got nil")
			}
			if !tc.expectIdentity && gotIdentity != nil {
				t.Errorf("expected no identity in context, got %v", gotIdentity)
			}
		})
	}
}

func TestUnifiedAuthMiddleware_UserToken(t *testing.T) {
	userTokenSvc, err := NewUserTokenService(UserTokenConfig{})
	if err != nil {
		t.Fatalf("failed to create user token service: %v", err)
	}

	accessToken, _, _, err := userTokenSvc.GenerateTokenPair(
		"user-123", "test@example.com", "Test User", "member", ClientTypeWeb,
	)
	if err != nil {
		t.Fatalf("failed to generate tokens: %v", err)
	}

	cfg := AuthConfig{
		Mode:         "production",
		UserTokenSvc: userTokenSvc,
		Debug:        false,
	}

	middleware := UnifiedAuthMiddleware(cfg)

	var gotIdentity Identity
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = GetIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if gotIdentity == nil {
		t.Fatal("expected identity in context, got nil")
	}

	if gotIdentity.ID() != "user-123" {
		t.Errorf("expected user ID 'user-123', got %q", gotIdentity.ID())
	}

	if gotIdentity.Type() != "user" {
		t.Errorf("expected identity type 'user', got %q", gotIdentity.Type())
	}

	userIdentity, ok := gotIdentity.(UserIdentity)
	if !ok {
		t.Fatal("expected UserIdentity type")
	}

	if userIdentity.Email() != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", userIdentity.Email())
	}
}

func TestUnifiedAuthMiddleware_AgentToken(t *testing.T) {
	agentTokenSvc, err := NewAgentTokenService(AgentTokenConfig{})
	if err != nil {
		t.Fatalf("failed to create agent token service: %v", err)
	}

	agentToken, err := agentTokenSvc.GenerateAgentToken("agent-456", "project-789", []AgentTokenScope{ScopeAgentStatusUpdate}, nil)
	if err != nil {
		t.Fatalf("failed to generate agent token: %v", err)
	}

	cfg := AuthConfig{
		Mode:          "production",
		AgentTokenSvc: agentTokenSvc,
		Debug:         false,
	}

	middleware := UnifiedAuthMiddleware(cfg)

	t.Run("agent token via X-Scion-Agent-Token header", func(t *testing.T) {
		var gotIdentity Identity
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotIdentity = GetIdentityFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-456/status", nil)
		req.Header.Set("X-Scion-Agent-Token", agentToken)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		if gotIdentity == nil {
			t.Fatal("expected identity in context, got nil")
		}

		if gotIdentity.ID() != "agent-456" {
			t.Errorf("expected agent ID 'agent-456', got %q", gotIdentity.ID())
		}

		if gotIdentity.Type() != "agent" {
			t.Errorf("expected identity type 'agent', got %q", gotIdentity.Type())
		}
	})
}

func TestUnifiedAuthMiddleware_HealthEndpointsSkipped(t *testing.T) {
	// Configure middleware with no auth methods enabled
	cfg := AuthConfig{
		Mode: "production",
	}

	middleware := UnifiedAuthMiddleware(cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Health endpoints should pass without auth
	healthPaths := []string{"/healthz", "/readyz"}
	for _, path := range healthPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200 for %s, got %d", path, rec.Code)
			}
		})
	}
}

func TestUnifiedAuthMiddleware_CLIAuthEndpointsSkipped(t *testing.T) {
	// Configure middleware with no auth methods enabled
	cfg := AuthConfig{
		Mode: "production",
	}

	middleware := UnifiedAuthMiddleware(cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// CLI OAuth endpoints should pass without auth (pre-login endpoints)
	cliAuthPaths := []string{"/api/v1/auth/cli/authorize", "/api/v1/auth/cli/token"}
	for _, path := range cliAuthPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200 for %s, got %d", path, rec.Code)
			}
		})
	}
}

func TestUnifiedAuthMiddleware_BrokerAuthPassthrough(t *testing.T) {
	// Configure middleware with no auth methods enabled
	cfg := AuthConfig{
		Mode:  "production",
		Debug: false,
	}

	middleware := UnifiedAuthMiddleware(cfg)

	var passedThrough bool
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passedThrough = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("request with X-Scion-Broker-ID passes through", func(t *testing.T) {
		passedThrough = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-brokers/test-host/heartbeat", nil)
		req.Header.Set("X-Scion-Broker-ID", "test-host-id")
		req.Header.Set("X-Scion-Timestamp", "1234567890")
		req.Header.Set("X-Scion-Nonce", "test-nonce")
		req.Header.Set("X-Scion-Signature", "test-signature")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !passedThrough {
			t.Error("expected request with X-Scion-Broker-ID to pass through to next handler")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("request without any auth is rejected", func(t *testing.T) {
		passedThrough = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-brokers/test-host/heartbeat", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if passedThrough {
			t.Error("expected request without auth to be rejected")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}
	})
}

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		token    string
		expected tokenType
	}{
		{apiclient.DevTokenPrefix + "abc123", tokenTypeDev},
		{"scion_pat_abc123def456", tokenTypeUAT},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", tokenTypeUser},
		{"random-string", tokenTypeUnknown},
		{"", tokenTypeUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.token[:min(20, len(tc.token))], func(t *testing.T) {
			got := detectTokenType(tc.token)
			if got != tc.expected {
				t.Errorf("expected token type %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestIdentityFromContext(t *testing.T) {
	t.Run("no identity", func(t *testing.T) {
		ctx := context.Background()
		identity := GetIdentityFromContext(ctx)
		if identity != nil {
			t.Errorf("expected nil identity, got %v", identity)
		}
	})

	t.Run("user identity", func(t *testing.T) {
		user := &DevUser{id: DevUserID}
		ctx := context.WithValue(context.Background(), userContextKey{}, user)
		identity := GetIdentityFromContext(ctx)
		if identity == nil {
			t.Fatal("expected identity, got nil")
		}
		if identity.ID() != DevUserID {
			t.Errorf("expected ID %q, got %q", DevUserID, identity.ID())
		}
	})

	t.Run("agent identity", func(t *testing.T) {
		agent := &AgentTokenClaims{}
		agent.Subject = "agent-123"
		agent.ProjectID = "project-456"
		ctx := context.WithValue(context.Background(), agentContextKey{}, agent)
		identity := GetIdentityFromContext(ctx)
		if identity == nil {
			t.Fatal("expected identity, got nil")
		}
		if identity.ID() != "agent-123" {
			t.Errorf("expected ID 'agent-123', got %q", identity.ID())
		}
	})
}

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name           string
		userRole       string
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name:           "admin has admin role",
			userRole:       "admin",
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "member has member role",
			userRole:       "member",
			requiredRoles:  []string{"member"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "member lacks admin role",
			userRole:       "member",
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "admin or member accepted",
			userRole:       "member",
			requiredRoles:  []string{"admin", "member"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := NewAuthenticatedUser("user-123", "test@example.com", "Test", tc.userRole, "web")

			handler := RequireRole(tc.requiredRoles...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			ctx := context.WithValue(context.Background(), userContextKey{}, user)
			ctx = contextWithIdentity(ctx, user)
			req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// newTestGCPCfgService builds a GCPIdentityService backed by the supplied fake
// validator for middleware routing tests.
func newMiddlewareGCPService(t *testing.T, fake OIDCValidator) *GCPIdentityService {
	t.Helper()
	svc, err := NewGCPIdentityService(testGCPAudience, testAllowlist(), fake)
	if err != nil {
		t.Fatalf("NewGCPIdentityService: %v", err)
	}
	return svc
}

func TestUnifiedAuthMiddleware_GCPIdentity_AllowlistedSA(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	cfg := AuthConfig{
		Mode:           "production",
		GCPIdentitySvc: newMiddlewareGCPService(t, fake),
	}
	middleware := UnifiedAuthMiddleware(cfg)

	var gotIdentity Identity
	var gotAuthType interface{}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = GetIdentityFromContext(r.Context())
		gotAuthType = r.Context().Value(logging.AuthTypeKey{})
		w.WriteHeader(http.StatusOK)
	}))

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
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.calls != 1 {
		t.Errorf("expected GCP validator to be called once, got %d", fake.calls)
	}
	if gotIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if gotIdentity.ID() != GCPIdentityUserID(testAllowedSAEmail) {
		t.Errorf("identity id = %q, want %q", gotIdentity.ID(), GCPIdentityUserID(testAllowedSAEmail))
	}
	scoped, ok := gotIdentity.(*ScopedUserIdentity)
	if !ok {
		t.Fatalf("expected *ScopedUserIdentity, got %T", gotIdentity)
	}
	if scoped.ScopedProjectID() != testAllowedProjectID {
		t.Errorf("project id = %q, want %q", scoped.ScopedProjectID(), testAllowedProjectID)
	}
	if gotAuthType != AuthTypeGCPIdentity {
		t.Errorf("auth type = %v, want %q", gotAuthType, AuthTypeGCPIdentity)
	}
}

func TestUnifiedAuthMiddleware_GCPIdentity_NonAllowlistedSA(t *testing.T) {
	fake := &fakeOIDCValidator{payload: validGooglePayload(testNotAllowedSAEmail)}
	cfg := AuthConfig{
		Mode:           "production",
		GCPIdentitySvc: newMiddlewareGCPService(t, fake),
	}
	middleware := UnifiedAuthMiddleware(cfg)

	var gotIdentity Identity
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = GetIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	token := makeUnsignedJWT(t, map[string]interface{}{
		"iss":   googleIssuerHTTPS,
		"aud":   testGCPAudience,
		"email": testNotAllowedSAEmail,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-allowlisted SA, got %d", rec.Code)
	}
	if gotIdentity != nil {
		t.Error("expected no identity for rejected GCP token")
	}
}

func TestUnifiedAuthMiddleware_GCPIdentity_NilSvcFallsThrough(t *testing.T) {
	// With GCPIdentitySvc nil, a Google-issued JWT must fall through to the
	// existing user-JWT path and fail there exactly as before (no behavior
	// change when the feature is unconfigured).
	userTokenSvc, err := NewUserTokenService(UserTokenConfig{})
	if err != nil {
		t.Fatalf("user token service: %v", err)
	}
	cfg := AuthConfig{
		Mode:         "production",
		UserTokenSvc: userTokenSvc,
		// GCPIdentitySvc deliberately nil
	}
	middleware := UnifiedAuthMiddleware(cfg)

	var gotIdentity Identity
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = GetIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	token := makeUnsignedJWT(t, map[string]interface{}{
		"iss":   googleIssuerHTTPS,
		"aud":   testGCPAudience,
		"email": testAllowedSAEmail,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (user-JWT validation failure), got %d", rec.Code)
	}
	if gotIdentity != nil {
		t.Error("expected no identity when feature unconfigured")
	}
}

func TestUnifiedAuthMiddleware_GCPIdentity_DoesNotDivertOtherTokens(t *testing.T) {
	// Regression guard: with GCPIdentitySvc configured, NON-Google tokens must
	// NOT be routed to the GCP validator.
	fake := &fakeOIDCValidator{payload: validGooglePayload(testAllowedSAEmail)}
	gcpSvc := newMiddlewareGCPService(t, fake)

	devToken := "scion_dev_test_token_12345678901234567890123456789012"

	userTokenSvc, err := NewUserTokenService(UserTokenConfig{})
	if err != nil {
		t.Fatalf("user token service: %v", err)
	}
	userAccessToken, _, _, err := userTokenSvc.GenerateTokenPair(
		"user-123", "test@example.com", "Test User", "member", ClientTypeWeb,
	)
	if err != nil {
		t.Fatalf("generate user tokens: %v", err)
	}

	cfg := AuthConfig{
		Mode:           "production",
		DevAuthEnabled: true,
		DevAuthToken:   devToken,
		UserTokenSvc:   userTokenSvc,
		GCPIdentitySvc: gcpSvc,
	}
	middleware := UnifiedAuthMiddleware(cfg)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"dev token", "Bearer " + devToken, http.StatusOK},
		{"scion-hub user JWT", "Bearer " + userAccessToken, http.StatusOK},
		{"scion_pat_ UAT routes to UAT (not GCP)", "Bearer scion_pat_abc123def456", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := fake.calls
			req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			req.Header.Set("Authorization", tc.authHeader)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if fake.calls != before {
				t.Errorf("GCP validator must NOT be invoked for %s; calls went %d -> %d", tc.name, before, fake.calls)
			}
		})
	}
}

func TestIsEmailAuthorized(t *testing.T) {
	tests := []struct {
		name              string
		email             string
		authorizedDomains []string
		adminEmails       []string
		expected          bool
	}{
		{
			name:              "empty domains allows all",
			email:             "user@example.com",
			authorizedDomains: []string{},
			expected:          true,
		},
		{
			name:              "nil domains allows all",
			email:             "user@example.com",
			authorizedDomains: nil,
			expected:          true,
		},
		{
			name:              "matching domain",
			email:             "user@example.com",
			authorizedDomains: []string{"example.com"},
			expected:          true,
		},
		{
			name:              "non-matching domain",
			email:             "user@other.com",
			authorizedDomains: []string{"example.com"},
			expected:          false,
		},
		{
			name:              "multiple domains - match first",
			email:             "user@example.com",
			authorizedDomains: []string{"example.com", "company.org"},
			expected:          true,
		},
		{
			name:              "multiple domains - match second",
			email:             "user@company.org",
			authorizedDomains: []string{"example.com", "company.org"},
			expected:          true,
		},
		{
			name:              "multiple domains - no match",
			email:             "user@other.com",
			authorizedDomains: []string{"example.com", "company.org"},
			expected:          false,
		},
		{
			name:              "case insensitive - uppercase domain config",
			email:             "user@example.com",
			authorizedDomains: []string{"EXAMPLE.COM"},
			expected:          true,
		},
		{
			name:              "case insensitive - uppercase email domain",
			email:             "user@EXAMPLE.COM",
			authorizedDomains: []string{"example.com"},
			expected:          true,
		},
		{
			name:              "invalid email - no @",
			email:             "notanemail",
			authorizedDomains: []string{"example.com"},
			expected:          false,
		},
		{
			name:              "email with subdomain",
			email:             "user@sub.example.com",
			authorizedDomains: []string{"example.com"},
			expected:          false,
		},
		{
			name:              "email with subdomain - matching subdomain",
			email:             "user@sub.example.com",
			authorizedDomains: []string{"sub.example.com"},
			expected:          true,
		},
		{
			name:              "admin email bypasses domain restriction",
			email:             "admin@personal.dev",
			authorizedDomains: []string{"example.com"},
			adminEmails:       []string{"admin@personal.dev"},
			expected:          true,
		},
		{
			name:              "admin email bypass is case insensitive",
			email:             "Admin@Personal.Dev",
			authorizedDomains: []string{"example.com"},
			adminEmails:       []string{"admin@personal.dev"},
			expected:          true,
		},
		{
			name:              "non-admin from unauthorized domain still rejected",
			email:             "user@personal.dev",
			authorizedDomains: []string{"example.com"},
			adminEmails:       []string{"admin@personal.dev"},
			expected:          false,
		},
		{
			name:              "admin email with no domain restrictions",
			email:             "admin@anywhere.com",
			authorizedDomains: []string{},
			adminEmails:       []string{"admin@anywhere.com"},
			expected:          true,
		},
		{
			name:              "wildcard matches single subdomain",
			email:             "user@foo.altostrat.com",
			authorizedDomains: []string{"*.altostrat.com"},
			expected:          true,
		},
		{
			name:              "wildcard matches nested subdomain",
			email:             "user@foo.bar.altostrat.com",
			authorizedDomains: []string{"*.altostrat.com"},
			expected:          true,
		},
		{
			name:              "wildcard does not match bare domain",
			email:             "user@altostrat.com",
			authorizedDomains: []string{"*.altostrat.com"},
			expected:          false,
		},
		{
			name:              "wildcard is case insensitive",
			email:             "user@FOO.ALTOSTRAT.COM",
			authorizedDomains: []string{"*.altostrat.com"},
			expected:          true,
		},
		{
			name:              "wildcard does not match unrelated domain",
			email:             "user@notaltostrat.com",
			authorizedDomains: []string{"*.altostrat.com"},
			expected:          false,
		},
		{
			name:              "wildcard alongside exact domain",
			email:             "user@sub.example.com",
			authorizedDomains: []string{"company.org", "*.example.com"},
			expected:          true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isEmailAuthorized(tc.email, tc.authorizedDomains, tc.adminEmails)
			if result != tc.expected {
				t.Errorf("isEmailAuthorized(%q, domains=%v, admins=%v) = %v, expected %v",
					tc.email, tc.authorizedDomains, tc.adminEmails, result, tc.expected)
			}
		})
	}
}
