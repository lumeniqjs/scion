# mc-s435-p1-scion-hub-gcp-identity-auth -- Final Report

> Hub inbound GCP workload-identity authentication (REFIRE). Operates on
> `lumeniqjs/scion`. Feature ships DARK -- breaks nothing until deployed +
> enabled. Date: 2026-05-28.

## Summary

Added Google Cloud workload-identity as a new, ADDITIVE inbound authentication
type on the Scion Hub. A caller running under a trusted GCP service account
(seeded: MC's `mc-cloud-run-invoker`) can now authenticate with a short-lived
Google OIDC identity token instead of a static `scion_pat_` UAT, eliminating
the recurring human-in-the-loop PAT rotation. Every existing auth path is
untouched. The feature is OFF by default; it only activates when a Hub binary
carrying this code is deployed AND `SCION_SERVER_GCP_IDENTITY_ENABLED=true`.

## Push-access fail-fast (Phase 0)

PASSED. The cross-repo proxy unblock (mc-S443) is in place: `git push origin
HEAD:main` against the `lumeniqjs/scion` remote succeeds. Verified probe commit
`f66b8f4` landed on scion `main` via the GitHub API. No `mc_github_write_file`
fallback was needed.

## Files added / changed + commit SHAs

All commits on `lumeniqjs/scion` `main`:

| SHA | Phase | Change |
| --- | --- | --- |
| `f66b8f4` | 0 | push-access probe + Phase 0 handoff stub |
| `2006dc0` | 1 | `pkg/hub/gcpidentityauth.go` (+ `_test.go`): verifier + allowlist |
| `0bfd1e3` | 2 | `pkg/hub/auth.go`, `identity.go`, `auth_test.go`: additive middleware routing |
| `79b5a57` | 3 | `pkg/hub/server.go`, `cmd/server_foreground.go` (+ `cmd/server_gcp_identity_test.go`): config wiring + SA allowlist seed |
| `fcbcbd2` | 4 | `pkg/hub/gcpidentityauth_integration_test.go`: end-to-end + authz-scoping regression |
| (this commit) | 6/7 | deploy runbook, docs (`auth.md`), report, Phase 0 final findings |

Production code added/changed:
- `pkg/hub/gcpidentityauth.go` (NEW) -- `GCPIdentityService`, injectable
  `OIDCValidator`, `GCPIdentityGrant`, fail-closed `ValidateToken`,
  `peekUnverifiedIssuer`, pinned `GCPIdentityDefaultAudience`, and the
  code-defined `DefaultGCPIdentityAllowlist()` seed.
- `pkg/hub/auth.go` -- `AuthConfig.GCPIdentitySvc` field (nil-safe) + the
  additive "Step 3.5" routing block (Google-iss peek -> GCP verifier).
- `pkg/hub/identity.go` -- `AuthTypeGCPIdentity = "gcp-identity"` constant.
- `pkg/hub/server.go` -- `ServerConfig.GCPIdentityAudience` +
  `GCPIdentityAllowlist`; guarded service construction (feature off unless both
  set).
- `cmd/server_foreground.go` -- `resolveGCPIdentityAuth()` env resolver +
  wiring into `hub.ServerConfig`.

## Design decisions (security-sensitive)

- **Fail closed everywhere.** Every error path in `ValidateToken` returns an
  error -> `401`; a partially-verified token never yields an identity.
- **Issuer checked explicitly.** `idtoken.Validate` verifies signature +
  audience + expiry but NOT `iss`, so the verifier independently requires a
  Google issuer.
- **Audience double-checked.** The configured audience is passed to
  `idtoken.Validate` AND re-asserted against `payload.Audience` (defence in
  depth). An empty audience is rejected at construction time (an empty audience
  would make `idtoken.Validate` skip the aud check entirely).
- **Allowlist is the sole authorization boundary.** Only enrolled SA emails
  authenticate; a cryptographically valid token from any other SA is `401`. The
  allowlist is code-defined so it is reviewed in a PR.
- **Synthetic principal is least-privilege.** The SA maps to a
  `ScopedUserIdentity` (id `gcp-sa:<email>`, role `service` -- NOT `admin`,
  which would trigger the authz admin bypass) carrying the grant's project +
  scopes, mirroring `UATSvc.ValidateToken`.
- **Routing peek only.** The unverified `iss` is used ONLY to decide whether to
  hand the token to the GCP verifier; it is never trusted for authentication.
- **Defensive scope copy.** Allowlist scope slices are copied at construction
  and at identity creation so later mutation cannot widen an authenticated
  identity.

## Existing auth tests pass unchanged (additive proof)

- `go build ./...`: GREEN.
- `go vet ./pkg/hub/`: GREEN.
- Targeted auth suites GREEN (27.9s), including the spec-mandated
  `pkg/hub/auth_test.go` + `handlers_auth_test.go`, plus authz, UAT, broker,
  permissions, envsecret-authz, principals, and the new GCP identity tests:
  `go test ./pkg/hub/ -run 'Auth|Token|UAT|GCPIdentity|Identity|Authz|RequireRole|Broker|DetectTokenType|Permission|EnvSecret|Principals|Remediation'`
- `go test ./pkg/hub/auth` (device-flow subpkg): GREEN.
- `go test ./cmd/ -run TestResolveGCPIdentityAuth`: GREEN.

New tests: `gcpidentityauth_test.go` (verifier unit tests: valid allowlisted SA,
non-allowlisted SA, wrong audience [validator-reject + defence-in-depth], wrong
issuer, expired, tampered signature, malformed, missing/unverified email,
case-insensitive email, misconfigured grant, nil-service, scope-copy);
`auth_test.go` additions (routing regression on every token type: dev / user-JWT
/ UAT not diverted, Google-iss routed, nil-svc fall-through);
`gcpidentityauth_integration_test.go` (end-to-end through middleware +
`RequireUserAuth`; authz scoping matches a UAT).

### Pre-existing, unrelated failures in the full suite

The FULL `go test ./pkg/hub/` run reports 6 failures that are NOT caused by this
work and are NOT auth-related:
`TestCreateProject_SharedWorkspace_SetsLabelAndInitFilesystem`,
`TestCloneSharedWorkspaceProject_Success`,
`TestCreateProject_AutoAssociatesGitHubInstallation`,
`TestProjectWorkspace{List,Upload,Archive}_SharedWorkspaceAllowed`.
They shell out to the real `git` binary (e.g. `git commit --allow-empty`) which
fails in this sandbox environment. VERIFIED pre-existing: they fail identically
on the clean base commit `1c96daa` (checked via `git worktree`). None of them
touch the auth code paths this spec changed.

## Phase 5 -- Hub image (chat-dispatched, NOT push-triggered)

CONFIRMED: `.github/workflows/build-images.yml` is `workflow_dispatch` only;
push-to-main does NOT build the Hub image, and `ci.yml` does not either. After
these commits land, the orchestrating chat dispatches:

```
mc_github_dispatch_workflow(owner=lumeniqjs, repo=scion,
  workflow_id=build-images.yml, ref=main,
  inputs={ target: "hub", registry: "ghcr.io/lumeniqjs", tag: "<tag>", platform: "all" })
```

Resulting image: `ghcr.io/lumeniqjs/scion-hub:<tag>` (built FROM
`ghcr.io/lumeniqjs/scion-base:<tag>` -- dispatch `target=common` if a matching
base does not already exist). No build config was touched, so no build commit.

## Phase 6 -- Deploy runbook (operator-gated)

See `mc-s435-p1-scion-hub-gcp-identity-auth-deploy-runbook.md`. NOT executed
from this session. Summary: pull the new image on `scion-substrate-01`, set
`SCION_SERVER_GCP_IDENTITY_ENABLED=true` +
`SCION_SERVER_GCP_IDENTITY_AUDIENCE=https://scion-hub.lumeniq.ai`, restart, then
probe with an impersonated identity token expecting auth to PASS (a 400/403 body
or authorization error, NOT a 401).

## Ships dark -- breaks nothing

The feature is OFF until BOTH (a) a Hub binary carrying this code is deployed AND
(b) `SCION_SERVER_GCP_IDENTITY_ENABLED=true`. With it off, `GCPIdentitySvc` is
nil and `UnifiedAuthMiddleware` skips the new block entirely; a Google-issued
token simply falls through to the existing user-JWT path and fails there exactly
as before. Rollback is unsetting the env var and restarting.

## Authorization note (boundary of this spec)

This spec delivers the AUTHENTICATION path. The minted `gcp-sa:<email>`
principal is project + scope scoped like a PAT, but it has no backing
user/ownership/group membership, so policy-gated actions will be DENIED until an
operator grants the `gcp-sa:<email>` principal the needed policies (or enrolls
it in the project's members group). That authorization wiring is a follow-up,
deliberately out of scope here.

## Follow-on (separate spec, in lumeniqjs/mission-control, AFTER Hub deploy)

`mc-S{NEXT}-P0-scion-client-gcp-identity`: switch `scion-client.ts` to mint a GCP
OIDC ID token with **audience = `https://scion-hub.lumeniq.ai`** (must match the
Hub config exactly) via the same workload-identity path used for Cloud Run
dispatch (mc-S66), and send `Authorization: Bearer <oidc>` instead of
`Bearer ${SCION_PAT}`. Feature-flag via `SCION_AUTH_MODE=gcp_identity|pat`
(default `pat`) for safe cutover. Once validated end-to-end (including the
authorization grant for the SA principal), retire `SCION_PAT` from Doppler. This
follow-on does NOT fire until the Hub binary with this feature is deployed +
verified.
