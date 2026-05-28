# mc-s435-p1-scion-hub-gcp-identity-auth -- Phase 0 findings

Spec: Hub inbound GCP workload-identity authentication (REFIRE).
Repo: lumeniqjs/scion. Branch: main. Date: 2026-05-28.

## Phase 0 actions (all completed)

1. Spec read in full. ACK.
2. `git remote -v`: origin resolves to the per-fire proxy
   (`http://local_proxy@127.0.0.1:.../git/lumeniqjs/scion`); `github` remote is
   `https://github.com/lumeniqjs/scion.git`. CONFIRMED on lumeniqjs/scion.
3. PUSH-ACCESS FAIL-FAST: PASSED. The no-op probe commit pushed successfully
   (`f66b8f4` on scion `main`, verified via GitHub API). The cross-repo proxy
   unblock (mc-S443) is in place -- Go work proceeded.
4. `extractBearerToken` integration line CONFIRMED: `pkg/hub/auth.go` matches the
   spec verbatim. The GCP routing block was inserted as "Step 3.5", immediately
   after `token := extractBearerToken(r)` + empty-token handling and before
   `switch detectTokenType(token)`.
5. Build env: module cache started ~empty but network module download WORKS;
   `go build ./...` is green. Go 1.25.4.

## Preserved-finding re-confirmation

- `google.golang.org/api v0.259.0` is a direct dep; `idtoken` package present at
  `.../api@v0.259.0/idtoken`. `idtoken.Validate(ctx, token, aud)` verifies
  signature + audience + expiry against Google's CACHED JWKS (caching is on by
  default via `defaultValidator`). IMPORTANT: it does NOT verify `iss`, so the
  verifier checks the Google issuer explicitly.
- Auth model: `ScopedUserIdentity` (pkg/hub/identity.go) = `UserIdentity` +
  projectID + scopes, constructed via `NewScopedUserIdentity`. UAT path
  (`useraccesstoken.go`) is the construction template mirrored here.
- AuthConfig is built in `pkg/hub/server.go` (~line 731), NOT `cmd/hub_auth.go`
  (that file is the CLI login command). `cmd/server_foreground.go` builds
  `hub.ServerConfig` and is where env wiring lives.
- Authz: a `ScopedUserIdentity` is gated by `enforceUATConstraints` (project +
  scope) and `Role()=="admin"` is an ADMIN BYPASS -> the synthetic SA principal
  uses role `service` (NOT admin) to stay least-privilege / fail-closed.

## Phase 5 build-trigger re-confirmation

`.github/workflows/build-images.yml` is `workflow_dispatch`/`workflow_call` ONLY
(inputs `registry`, `target` [choice incl. `hub`], `tag`, `platform`). `ci.yml`
does NOT build the hub image. The hub image is `<registry>/scion-hub:<tag>`
(built FROM `scion-base:<tag>`). Phase 5 is chat-dispatched post-commit; the
sandbox needs no Docker/GHCR tooling.
