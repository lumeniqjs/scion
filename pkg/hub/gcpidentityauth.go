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
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/api/idtoken"
)

// This file implements an ADDITIVE inbound authentication type: Google Cloud
// workload-identity. It lets a caller running under a GCP service account (for
// example mc-api's mc-cloud-run-invoker SA) authenticate to the Hub with a
// short-lived Google OIDC identity token instead of a static scion_pat_ UAT,
// eliminating long-lived-credential rotation toil.
//
// SECURITY NOTE: this is authentication code. Every code path below FAILS
// CLOSED -- any verification problem returns an error and the caller maps it to
// a 401. The trusted-SA allowlist is the sole authorization boundary: only
// explicitly enrolled service-account emails authenticate; everything else is
// rejected even when the Google signature is otherwise valid.

const (
	// googleIssuerHTTPS and googleIssuerBare are the only issuers accepted for a
	// Google-issued OIDC identity token. idtoken.Validate does NOT check the
	// issuer, so this package verifies it explicitly.
	googleIssuerHTTPS = "https://accounts.google.com"
	googleIssuerBare  = "accounts.google.com"

	// GCPIdentityDefaultAudience is the pinned audience (aud claim) the Hub
	// expects on inbound GCP identity tokens. The MC client (follow-on spec)
	// MUST mint its OIDC tokens with exactly this audience -- a mismatch is a
	// silent 401.
	GCPIdentityDefaultAudience = "https://scion-hub.lumeniq.ai"

	// gcpIdentityRole is the role assigned to the synthetic principal produced
	// for an authenticated service account. It is deliberately NOT "admin": the
	// authz layer grants an admin bypass to role=="admin", and a service
	// account must never receive that bypass. Access for this principal is
	// governed entirely by the UAT-style project + scope constraints carried on
	// the ScopedUserIdentity plus any explicit policy grants.
	gcpIdentityRole = "service"

	// gcpIdentitySubjectPrefix namespaces GCP service-account principals in
	// display names and deterministic UUID inputs.
	gcpIdentitySubjectPrefix = "gcp-sa:"
)

// gcpIdentityNamespace is a fixed v5 namespace so the backing-user UUID for a
// given service-account email is stable across restarts and across the verifier
// and startup seed.
var gcpIdentityNamespace = uuid.MustParse("7bdf5220-5b7e-4d57-9967-b6045c3fba44")

// GCPIdentityUserID returns the deterministic backing-user UUID for a
// service-account email. The mapping is case-insensitive and namespaced away
// from human users.
func GCPIdentityUserID(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	return uuid.NewSHA1(gcpIdentityNamespace, []byte(gcpIdentitySubjectPrefix+e)).String()
}

// ErrGCPIdentityInvalid is returned for any verification failure on a GCP
// identity token (bad signature, wrong audience, wrong issuer, expired,
// malformed, missing/unverified email). Callers map it to a 401.
var ErrGCPIdentityInvalid = errors.New("invalid GCP identity token")

// ErrGCPIdentityNotAllowed is returned when a token is cryptographically valid
// and Google-issued but its service-account email is not in the trusted-SA
// allowlist. Callers map it to a 401 (it is distinguished from
// ErrGCPIdentityInvalid only for logging/audit clarity).
var ErrGCPIdentityNotAllowed = errors.New("service account not in GCP identity allowlist")

// OIDCValidator abstracts Google OIDC verification so tests can inject a fake.
// The production implementation wraps idtoken.Validate, which verifies the
// token signature, audience and expiry against Google's cached JWKS.
type OIDCValidator interface {
	Validate(ctx context.Context, token, audience string) (*idtoken.Payload, error)
}

// googleOIDCValidator is the production OIDCValidator. idtoken.Validate uses a
// process-wide caching HTTP client for Google's cert endpoints, so the hot path
// makes no network call once the JWKS is cached.
type googleOIDCValidator struct{}

func (googleOIDCValidator) Validate(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	return idtoken.Validate(ctx, token, audience)
}

// GCPIdentityGrant maps a trusted service account to the project it acts within
// and the action scopes it is allowed to exercise. Scopes use the same
// vocabulary as UATs (e.g. "agent:create", "agent:read").
type GCPIdentityGrant struct {
	ProjectID string
	Scopes    []string
}

// GCPIdentityService validates inbound Google OIDC identity tokens against a
// trusted service-account allowlist and maps them to project-scoped principals.
type GCPIdentityService struct {
	audience  string                      // expected aud claim (the Hub's identity)
	allowlist map[string]GCPIdentityGrant // lower-cased SA email -> grant
	validator OIDCValidator               // injectable; production = googleOIDCValidator{}
}

// NewGCPIdentityService constructs a GCPIdentityService.
//
//   - audience MUST be non-empty; an empty audience is rejected because
//     idtoken.Validate skips the audience check when audience == "", which would
//     accept tokens minted for any other relying party. We refuse to build a
//     service that could do that.
//   - validator may be nil, in which case the production googleOIDCValidator is
//     used.
//   - allowlist keys are normalised to lower-case, trimmed emails.
func NewGCPIdentityService(audience string, allowlist map[string]GCPIdentityGrant, validator OIDCValidator) (*GCPIdentityService, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return nil, fmt.Errorf("gcp identity: audience is required")
	}
	if validator == nil {
		validator = googleOIDCValidator{}
	}
	norm := make(map[string]GCPIdentityGrant, len(allowlist))
	for email, grant := range allowlist {
		key := strings.ToLower(strings.TrimSpace(email))
		if key == "" {
			continue
		}
		// Defensive copy of the scope slice so later mutation of the caller's
		// data cannot widen an authenticated identity's scopes.
		scopes := append([]string(nil), grant.Scopes...)
		norm[key] = GCPIdentityGrant{ProjectID: grant.ProjectID, Scopes: scopes}
	}
	return &GCPIdentityService{
		audience:  audience,
		allowlist: norm,
		validator: validator,
	}, nil
}

// ValidateToken verifies a Google OIDC identity token and returns a scoped
// identity. It FAILS CLOSED: every error path returns an error and never a
// partially-verified identity.
//
// Verification order (all must pass):
//  1. Signature + audience + expiry via the injected validator (Google JWKS).
//  2. Issuer is one of Google's accepted issuers (idtoken.Validate does NOT
//     check iss, so it is checked here).
//  3. Audience matches the configured audience exactly (defence in depth on top
//     of the validator's own check).
//  4. The "email" claim is present and, if "email_verified" is present, true.
//  5. The email is in the trusted-SA allowlist (the authorization boundary).
func (s *GCPIdentityService) ValidateToken(ctx context.Context, token string) (*ScopedUserIdentity, error) {
	if s == nil || s.validator == nil {
		return nil, ErrGCPIdentityInvalid
	}
	if s.audience == "" {
		// A misconfigured service must never validate against an empty audience.
		return nil, ErrGCPIdentityInvalid
	}
	if strings.TrimSpace(token) == "" {
		return nil, ErrGCPIdentityInvalid
	}

	// 1. Cryptographic verification: signature + audience + expiry.
	payload, err := s.validator.Validate(ctx, token, s.audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGCPIdentityInvalid, err)
	}
	if payload == nil {
		return nil, ErrGCPIdentityInvalid
	}

	// 2. Issuer must be Google. idtoken.Validate does not enforce this.
	if !isGoogleIssuer(payload.Issuer) {
		return nil, fmt.Errorf("%w: unexpected issuer %q", ErrGCPIdentityInvalid, payload.Issuer)
	}

	// 3. Defence in depth: re-confirm the audience matches exactly. Never trust a
	// single check in auth code.
	if payload.Audience != s.audience {
		return nil, fmt.Errorf("%w: audience mismatch", ErrGCPIdentityInvalid)
	}

	// 4. Extract and validate the service-account email claim.
	email, _ := payload.Claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, fmt.Errorf("%w: missing email claim", ErrGCPIdentityInvalid)
	}
	if ev, ok := payload.Claims["email_verified"]; ok && !claimIsTrue(ev) {
		return nil, fmt.Errorf("%w: email not verified", ErrGCPIdentityInvalid)
	}

	// 5. Allowlist lookup -- the sole authorization boundary for this path.
	grant, ok := s.allowlist[email]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrGCPIdentityNotAllowed, email)
	}
	if grant.ProjectID == "" || len(grant.Scopes) == 0 {
		// A grant with no project or no scopes can authorize nothing; refuse to
		// mint an identity from it rather than mint an empty/ambiguous one.
		return nil, fmt.Errorf("%w: grant misconfigured for %s", ErrGCPIdentityInvalid, email)
	}

	// Map to a ScopedUserIdentity, mirroring UATSvc.ValidateToken. The backing
	// user has a stable UUID derived from the SA email and a non-admin role.
	user := NewAuthenticatedUser(
		GCPIdentityUserID(email),
		email,
		gcpIdentitySubjectPrefix+email,
		gcpIdentityRole,
		string(ClientTypeAPI),
	)
	scopes := append([]string(nil), grant.Scopes...)
	return NewScopedUserIdentity(user, grant.ProjectID, scopes), nil
}

// isGoogleIssuer reports whether iss is one of Google's accepted OIDC issuers.
func isGoogleIssuer(iss string) bool {
	return iss == googleIssuerHTTPS || iss == googleIssuerBare
}

// peekUnverifiedIssuer parses (WITHOUT verifying) the issuer claim of a JWT.
// It is used ONLY as a routing hint to decide whether to hand a bearer token to
// the GCP identity verifier. The token is fully verified afterwards inside
// ValidateToken; the unverified issuer is never trusted for authentication.
func peekUnverifiedIssuer(token string) string {
	payload, err := idtoken.ParsePayload(token)
	if err != nil || payload == nil {
		return ""
	}
	return payload.Issuer
}

// claimIsTrue interprets a JWT boolean-ish claim. Google encodes email_verified
// as a JSON boolean, but tolerate the string forms defensively.
func claimIsTrue(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

// DefaultGCPIdentityAllowlist returns the canonical built-in trusted-SA
// allowlist seed. Today it enrolls MC's dispatcher service account. Adding a
// future product principal is a one-line addition here (the allowlist is
// intentionally code-defined so changes are reviewed in a PR).
func DefaultGCPIdentityAllowlist() map[string]GCPIdentityGrant {
	return map[string]GCPIdentityGrant{
		"mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com": {
			ProjectID: "3152156d-67ef-415f-8ca5-903b446e2894",
			Scopes: []string{
				"agent:create",
				"agent:read",
				"agent:attach",
			},
		},
	}
}
