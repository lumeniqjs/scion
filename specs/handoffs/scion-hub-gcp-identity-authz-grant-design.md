# Scion Hub -- GCP-identity principal authorization grant (DESIGN)

> Design doc for the follow-up to mc-S435-P1. The implementation fire (next in
> this chain) writes the code against this design. NO code changes in this fire.
>
> Repo: lumeniqjs/scion. Date: 2026-05-28.
> Fire: e43b4b05-32f4-4046-b0ac-05e0c3908583 (substrate-executor / Opus).

## Problem statement

mc-S435-P1 shipped inbound GCP workload-identity AUTHENTICATION
(`pkg/hub/gcpidentityauth.go`). A trusted service account
(`mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com`)
authenticates and is mapped to a synthetic `*ScopedUserIdentity` with id
`gcp-sa:<email>`, role `service`, project `3152156d-67ef-415f-8ca5-903b446e2894`,
and scopes `[agent:dispatch, agent:read, agent:list, agent:stop]`.

The deploy runbook flagged the gap: that principal AUTHENTICATES but is then
DENIED by policy on real actions, because it has no project membership / role /
policy grant the authorization layer recognizes. This design specifies how to
grant it authorization at functional parity with the `scion_pat_` UAT principal
mc-api uses today.

---

## 1. Authorization model summary

### Authentication vs authorization are two separate layers

- AUTHENTICATION: `UnifiedAuthMiddleware` (`pkg/hub/auth.go:72`). The GCP-identity
  block is "Step 3.5" (`auth.go:165-193`): a Google-issued JWT is verified by
  `GCPIdentityService.ValidateToken` and the resulting `*ScopedUserIdentity` is
  placed in the request context. The UAT path is the `tokenTypeUAT` branch
  (`auth.go:216-233`), which calls `UserAccessTokenService.ValidateToken`.
- AUTHORIZATION: every protected handler calls
  `AuthzService.CheckAccess(ctx, identity, resource, action)`
  (`pkg/hub/authz.go:94`). This is where the gcp-identity principal is currently
  denied.

### Both UAT and GCP-identity produce the SAME identity shape

Both produce a `*ScopedUserIdentity` (`pkg/hub/identity.go:86-117`) -- a
`UserIdentity` wrapped with a `projectID` constraint and a `scopes []string`
constraint. The ONLY structural difference is the backing user:

- UAT (`pkg/hub/useraccesstoken.go:152-195`): looks up `token.UserID`, fetches
  the REAL `store.User`, and builds the identity with that user's real UUID id,
  real email, and real `role`. The token narrows that real user to a project +
  scopes.
- GCP-identity (`pkg/hub/gcpidentityauth.go:207-217`): builds a SYNTHETIC user
  with id `gcp-sa:<email>`, role `service`, that has NO corresponding row in any
  users / groups / policy tables.

### How CheckAccess decides for a user/scoped principal

`checkAccessForUser` (`authz.go:112-178`) runs, in order:

0. `enforceUATConstraints` (`authz.go:413-434`) -- if the identity is a
   `*ScopedUserIdentity`, enforce the project + scope constraints. The check
   computes `scope := resource.Type + ":" + action` and denies if the scope is
   missing or the resource is in another project. IMPORTANT: this gate only
   RESTRICTS; passing it returns `nil` and does NOT by itself authorize.
1. Admin bypass -- `user.Role() == "admin"`. (gcp-identity role is `service`, by
   deliberate design, so never bypasses here.)
2. Owner bypass -- `resource.OwnerID == user.ID()`.
3. (2.5) Ancestry bypass -- `user.ID()` appears in `resource.Ancestry`.
4. (2.6) Project owner/admin -- `isProjectOwnerOrAdmin(user.ID(), projectID)`
   (`authz.go:461-486`): the user is an owner/admin member of the project's
   explicit `project:<slug>:members` group.
5. Policy evaluation (`authz.go:157-177`) -- build principal refs
   `[{user, user.ID()}] + effective groups`, fetch bound policies via
   `GetPoliciesForPrincipals`, evaluate. No match -> `default deny`.

### Why the UAT principal is authorized today and the GCP principal is not

mc-api's UAT wraps a REAL user that IS authorized for the project -- in practice
the project owner/admin (so step 2.6 / owner bypass allows the action) -- and the
UAT merely narrows that to a project + scopes. The gcp-identity principal's
synthetic `gcp-sa:<email>` user matches NOTHING in steps 1-5, so after passing
the scope gate it falls through to `default deny`. This is the entire gap.

### DECISIVE constraint: authz principal ids are UUIDs in production

Production runs `entadapter.NewCompositeStore(sqlite, ent)`
(`cmd/server_foreground.go:633-676`). The CompositeStore overrides ALL group and
policy operations with the Ent-backed stores (`composite.go:38-45`). In the Ent
schema:

- `PolicyBinding.user_id` / `group_id` / `agent_id` are UUID columns with FK
  edges to `User` / `Group` / `Agent` (`pkg/ent/schema/policybinding.go:45-76`).
  `AddPolicyBinding` and `GetPoliciesForPrincipals` call `parseUUID` on the
  principal id (`pkg/store/entadapter/policy_store.go:302, 431`).
- Group membership member ids are UUIDs (`group_store.go:42`); `GetEffectiveGroups`
  parses the user id as a UUID (`group_store.go:713`).

Therefore the synthetic STRING id `gcp-sa:<email>` can never be an authorization
principal in the production store -- it is not a UUID, so every binding write and
every policy lookup keyed on it is silently dropped. Any grant (group membership
OR policy binding) requires the gcp-identity principal to carry a UUID as
`user.ID()`.

Two further store facts that shape the mechanism:

- `AddGroupMember` lazily creates an Ent "shadow" user from the base store via
  `ensureEntUser` (`composite.go:90-131`); `AddPolicyBinding` does NOT. So a
  policy must be bound to a GROUP that the user joins (the join creates the
  shadow), not bound directly to the user principal (which would hit a missing
  FK). `CreateUser` / `GetUser` are not overridden and write to the base SQLite
  store only.
- `AccessPolicy.scope_id` is a plain optional string with NO project FK
  (`pkg/ent/schema/policy.go:45`), so a project-scoped policy can be seeded even
  if the project row is not present in the Ent DB.

---

## 2. The grant mechanism (recommendation)

### Summary

At Hub startup, gated by the SAME feature flag that enables GCP-identity auth,
seed -- idempotently and code-defined -- for each allowlist entry:

1. a deterministic backing User (UUID derived from the SA email);
2. a dedicated explicit Group whose sole member is that user;
3. a project-scoped allow Policy whose actions are derived from the grant's
   scopes, bound to that group.

And make `GCPIdentityService.ValidateToken` mint the `*ScopedUserIdentity` with
the SAME deterministic UUID as `user.ID()` (instead of the `gcp-sa:<email>`
string), so authorization lookups key on the seeded principal.

This reuses the existing seed/grant primitives (`seedDevUser` for the user,
`CreateGroup` + `AddGroupMember` for membership, `seedPolicy`-style
`CreatePolicy` + `AddPolicyBinding`) -- the same pattern as
`seedDefaultPoliciesAndGroups` (`seed.go:29`) and
`createProjectMembersGroupAndPolicy` (`handlers.go:3564`). No new authz code path
is introduced; the policy engine does the granting.

### Why group-bound policy, not project-owner membership

Two grant shapes both reach parity (the scope gate is the outer least-privilege
bound in BOTH cases, since `enforceUATConstraints` runs first and limits the
principal to its project + scopes regardless of how broadly it is granted):

- (A) Add the SA user as an owner/admin of `project:<slug>:members` -> step 2.6
  `isProjectOwnerOrAdmin` bypass authorizes any in-scope action. This is the
  literal mirror of mc-api's project-owner UAT and is the lightest touch, BUT it
  confers project-owner-equivalent power that is bounded only by the scope gate;
  if the grant's scopes are later widened the SA silently gains owner powers.
- (B) RECOMMENDED: a dedicated group bound to a project-scoped policy whose
  actions are EXACTLY the grant's scopes. This is least privilege and defense in
  depth: the principal is limited by the scope gate AND by a policy that only
  allows the enumerated actions. Widening requires an explicit, reviewed change
  to the allowlist scopes (which drive the policy actions).

Recommend (B). It reuses the same primitives, ships with the binary, and fails
safe.

### Deterministic backing-user id

Add a helper in `gcpidentityauth.go`:

```
// gcpIdentityNamespace is a fixed v5 namespace so the backing-user UUID for a
// given SA email is stable across restarts and across the verifier and the seed.
var gcpIdentityNamespace = uuid.MustParse("<fixed-namespace-uuid>")

// GCPIdentityUserID returns the deterministic backing-user UUID for an SA email.
func GCPIdentityUserID(email string) string {
    e := strings.ToLower(strings.TrimSpace(email))
    return uuid.NewSHA1(gcpIdentityNamespace, []byte("gcp-sa:"+e)).String()
}
```

`ValidateToken` then builds the identity with `GCPIdentityUserID(email)` as the
id while keeping `Email()` and `DisplayName()` carrying the SA email for audit
clarity (the `gcp-sa:` namespacing moves into the display name; the auth-type log
marker is already `gcp-identity`). The role stays `service` (must NOT be admin).

### Scope -> policy-action mapping (and the scope-vocabulary reconciliation)

The seed derives the policy from the grant's scopes so the policy and the scope
gate stay in lockstep. Each scope is `resourceType:action`; group by resource
type and create one allow policy per resource type:

```
scope "agent:create" -> resourceType "agent", action "create"
scope "agent:read"   -> resourceType "agent", action "read"
scope "agent:attach" -> resourceType "agent", action "attach"
```

For the current allowlist, this yields one policy:
`{ScopeType:"project", ScopeID:<projectID>, ResourceType:"agent",
Actions:[...], Effect:"allow"}` bound to the SA's dedicated group. `matchesAction`
(`authz.go:352`) compares the bare verb against `Action(a)`, and the project
scope matches because `agentResource` sets `ParentType="project"`,
`ParentID=projectID` (`capabilities.go:53-63`).

CRITICAL FINDING -- the allowlist scopes must be reconciled before this works
end to end. The S435 allowlist scopes `[agent:dispatch, agent:read, agent:list,
agent:stop]` do NOT match the Hub's actual scope-gate vocabulary. The
gate value is `resource.Type + ":" + action` from each `CheckAccess` call, and
for the operations mc-api performs the real values are:

- create / "dispatch" an agent -> `ActionCreate` => `agent:create`
  (`handlers.go:445-455`); scion "dispatch" IS agent creation (it triggers
  `DispatchAgentCreate`).
- read agent status -> `ActionRead` => `agent:read` (`handlers.go:1453-1458`).
- stop / start / lifecycle -> `ActionAttach` => `agent:attach`
  (`handlers.go:4961-4982`).

No `CheckAccess` uses action `dispatch` or `list` on an agent resource, so
`agent:dispatch` and `agent:list` are inert today, and `agent:stop` does not gate
the stop action (`agent:attach` does). Only `agent:read` aligns. A scoped token
carrying only the S435 scopes would be denied by the scope GATE on create and on
stop, regardless of any policy grant -- and mc-api works today, so its live UAT
must actually carry `agent:create` / `agent:read` / `agent:attach`-style scopes.

Therefore the implementation fire MUST set the allowlist scopes to the Hub's real
gate vocabulary for mc-api's operations -- at minimum
`[agent:create, agent:read, agent:attach]` -- after confirming mc-api's actual
live UAT scopes (see Risks). Because the policy actions are derived from the
scopes, fixing the allowlist scopes fixes both the gate and the policy together.

### Idempotency

- User: `GetUser(uid)`; create only if `ErrNotFound` (mirror `seedDevUser`,
  `seed.go:108-126`). Role `service`, status `active`, email = SA email.
- Group: `GetGroupBySlug("gcp-identity:<email>")`; create if absent. Leave
  `ProjectID` empty (avoids the `ensureEntProject` path and any
  project-owner/admin ambiguity -- authorization comes from the bound policy, not
  the membership role). `AddGroupMember` with role `member` (idempotent; ignore
  `ErrAlreadyExists`) -- this also creates the Ent shadow user.
- Policy: look up by deterministic name `gcp-identity:<email>:<resourceType>`
  (mirror `seedPolicy`, `seed.go:75-102`); create if absent, else ensure
  `ScopeID` + `Actions` match. Bind to the group; ignore `ErrAlreadyExists`.

### Feature-flag gating (off by default)

The seed runs ONLY inside the existing
`if cfg.GCPIdentityAudience != "" && len(cfg.GCPIdentityAllowlist) > 0` block in
`pkg/hub/server.go:755`, which is reached only when
`SCION_SERVER_GCP_IDENTITY_ENABLED=true` (`resolveGCPIdentityAuth`,
`cmd/server_foreground.go:1444-1454`) produces a non-empty audience + allowlist.
With the flag off, no user/group/policy is seeded and the identity-id change is
inert (the GCP verifier is never constructed because `GCPIdentitySvc` stays nil).

---

## 3. Code locations (for the implementation fire)

| File | Function / site | Change |
| --- | --- | --- |
| `pkg/hub/gcpidentityauth.go` | new `GCPIdentityUserID(email)` + `gcpIdentityNamespace` | deterministic backing-user UUID helper |
| `pkg/hub/gcpidentityauth.go` | `ValidateToken` (~:207-217) | set the identity id to `GCPIdentityUserID(email)`; keep email/display-name for audit; role stays `service` |
| `pkg/hub/gcpidentityauth.go` | `DefaultGCPIdentityAllowlist` (~:254-265) | reconcile scopes to the Hub's real gate vocabulary (`agent:create, agent:read, agent:attach`, per Risks verification) |
| `pkg/hub/seed.go` (or new `pkg/hub/gcpidentityseed.go`) | new `seedGCPIdentityGrants(ctx, store, allowlist)` | seed user + dedicated group + project-scoped policy + binding per allowlist entry; idempotent; reuse existing primitives |
| `pkg/hub/server.go` | inside the `GCPIdentityAudience != "" && len(...) > 0` block (~:755-766) | call `seedGCPIdentityGrants(ctx, s, cfg.GCPIdentityAllowlist)` after the service is constructed; log seeded principal count |

No store-layer changes are required: `CreateUser`, `CreateGroup`,
`AddGroupMember`, `CreatePolicy`, `AddPolicyBinding` all already exist and behave
as needed (the group-binding path sidesteps the `AddPolicyBinding` shadow-user
gap). No Ent schema / migration change is required (`scope_id` has no FK; the
user/group/policy rows use existing tables).

---

## 4. Test plan (smallest set that proves parity)

All tests are store-backed unit tests in `pkg/hub`, mirroring the style of
`gcpidentityauth_integration_test.go` and `authz_integration_test.go`. Use an
in-memory CompositeStore (sqlite + ent) so the UUID/FK behavior is exercised
exactly as in production.

1. The regression test that WOULD HAVE FAILED before the grant
   (`TestGCPIdentityGrant_AuthorizesInScopeActions`):
   - Seed via `seedGCPIdentityGrants` for the test SA -> project P, scopes
     `[agent:create, agent:read, agent:attach]`.
   - Build the gcp-identity identity exactly as `ValidateToken` does (id =
     `GCPIdentityUserID(email)`, role `service`, project P, those scopes).
   - Create a test agent in project P. Assert
     `AuthzService.CheckAccess(identity, agentResource(agent), ActionRead)` is
     Allowed, and likewise for `ActionAttach`, and for
     `Resource{Type:"agent", ParentType:"project", ParentID:P}` + `ActionCreate`.
   - Pre-grant control: without the seed, the same three `CheckAccess` calls
     return `default deny`. (This is the test that the runbook gap describes.)

2. UAT parity (`TestGCPIdentityGrant_MatchesUATAuthorization`):
   - Stand up a UAT-backed `*ScopedUserIdentity` for a real user that is an
     owner/member authorized in project P with the same scopes.
   - Assert the gcp-identity principal's `CheckAccess` decisions match the UAT
     principal's for the same (resource, action) set (create/read/attach in P).

3. Scope-boundary + project-boundary enforcement
   (`TestGCPIdentityGrant_DeniesOutOfScopeAndCrossProject`):
   - `CheckAccess(identity, agentResource in P, ActionDelete)` -> denied
     (`agent:delete` not in scopes; scope gate).
   - `CheckAccess(identity, agentResource in OTHER project, ActionRead)` ->
     denied (project gate). (Extends the existing
     `TestGCPIdentity_AuthzScopingMatchesUAT`.)

4. Idempotency (`TestSeedGCPIdentityGrants_Idempotent`):
   - Run `seedGCPIdentityGrants` twice; assert exactly one user, one group, one
     membership, one policy, one binding (no duplicates, no error).

5. Feature-off no-op (`TestSeedGCPIdentityGrants_NotCalledWhenDisabled` /
   server-init test):
   - With `SCION_SERVER_GCP_IDENTITY_ENABLED` unset, assert no gcp-identity
     user/group/policy rows are created and `GCPIdentitySvc` is nil.

6. Deterministic id (`TestGCPIdentityUserID_StableAndUUID`):
   - `GCPIdentityUserID(email)` is a valid UUID, stable across calls, and
     case-insensitive on the email.

7. Update the two existing id assertions: `gcpidentityauth_test.go:116-117` and
   `auth_test.go:475-476` both assert `identity.ID() == gcpIdentitySubjectPrefix+email`;
   change both to `identity.ID() == GCPIdentityUserID(email)`. These are the only
   sites that key on the `gcp-sa:` prefix; production code uses it solely at the
   construction site (`gcpidentityauth.go:210`).

Run-green gate: `go build ./...`, `go vet ./pkg/hub/`, and the auth/authz suites
(`go test ./pkg/hub/ -run 'Auth|Authz|UAT|GCPIdentity|Identity|Seed|Permission'`).
Note the pre-existing, unrelated `git`-shelling project-workspace test failures
documented in the S435 report -- they are not auth-related.

---

## 5. Risks and edge cases

- HIGHEST PRIORITY -- scope-vocabulary correctness. The single most likely cause
  of "still denied after the grant" is the allowlist scopes not matching the
  Hub's real gate values. Before finalizing, the implementation fire MUST confirm
  mc-api's actual live UAT scopes (from the mission-control scion-client / the
  Doppler-provisioned `SCION_PAT`) and set `DefaultGCPIdentityAllowlist` scopes to
  the matching gate vocabulary (`agent:create`, `agent:read`, `agent:attach`, plus
  any others mc-api exercises). Because policy actions are derived from scopes,
  getting the scopes right fixes both layers. Keeping the inert
  `agent:dispatch/list/stop` strings is harmless but misleading; prefer replacing
  them.
- Fail-closed. The grant only ever ADDS allow policies for explicitly enrolled
  SAs scoped to one project + a fixed action set. If the seed fails (e.g., store
  error), it must log and continue best-effort like the existing seeds; the
  principal then simply stays denied (closed), never over-granted. The
  authentication layer is unchanged and still fails closed.
- Scope-boundary enforcement is preserved as the outer bound. `enforceUATConstraints`
  runs first on every request; even if a policy were broader than intended, the
  principal cannot act outside its project or its scopes. The recommended
  group-bound policy makes the policy itself least-privilege too (defense in
  depth).
- Role must remain `service`, never `admin`. An admin role would short-circuit
  CheckAccess at step 1 and bypass both the policy and (in effect) the intent of
  the scope set. The design keeps `gcpIdentityRole = "service"`.
- Identity-id change blast radius. Changing `user.ID()` from `gcp-sa:<email>` to a
  UUID is load-bearing (authz keys on it) and touches security-sensitive code.
  Mitigations: the UUID is a deterministic v5 hash of `gcp-sa:<email>`, so it
  remains 1:1 with the SA; audit retains the SA email via `Email()`/display name
  and the `gcp-identity` auth-type marker; only two existing test assertions
  change (item 7). No PRODUCTION code keys on the `gcp-sa:` id prefix -- it is
  used solely at the identity construction site (verified across pkg/ and cmd/).
- Feature flag off. With `SCION_SERVER_GCP_IDENTITY_ENABLED` unset, no seed runs
  and the verifier is never built (`GCPIdentitySvc` nil), so a Google-issued token
  falls through to the user-JWT path and fails exactly as before. Rollback is
  unsetting the env var and restarting (unchanged from S435).
- Project must exist for the grant to be meaningful. The policy is project-scoped
  but has no project FK, so the seed succeeds regardless; however the principal
  can only act on agents that actually live in project
  `3152156d-67ef-415f-8ca5-903b446e2894`. If mc-api's project id differs from the
  allowlist's `ProjectID`, the principal is correctly denied -- the
  implementation fire should confirm the project id matches mc-api's project.
- Stale shadow / re-seed. The seed is idempotent and converges (ensures
  scope/actions on re-run), so redeploys and allowlist edits are safe; removing an
  SA from the allowlist does NOT auto-revoke its seeded grant (a known limitation;
  call out as a future cleanup task if revocation-on-removal is desired).

## Expected outcome of the implementation fire

A scoped gcp-identity principal for an enrolled SA reaches `Allowed` on its
granted (resource, action) pairs in its project via the policy engine -- at
functional parity with mc-api's UAT -- while remaining denied outside its project
and scopes, with the whole grant gated off by default behind
`SCION_SERVER_GCP_IDENTITY_ENABLED`.
