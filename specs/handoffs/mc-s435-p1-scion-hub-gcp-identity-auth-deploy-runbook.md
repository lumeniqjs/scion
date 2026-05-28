# mc-s435-p1-scion-hub-gcp-identity-auth -- Deploy Runbook (OPERATOR-GATED)

> DO NOT run from an autonomous session. VM rollout is operator-gated.
> The feature ships DARK: until the new Hub binary is deployed AND the feature
> is enabled via env, nothing changes.

Repo: lumeniqjs/scion. Pinned audience: `https://scion-hub.lumeniq.ai`.
Trusted SA seed: `mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com`
(project `3152156d-67ef-415f-8ca5-903b446e2894`, scopes
`agent:dispatch, agent:read, agent:list, agent:stop`).

## Pre-req: build + push the new Hub image (chat-dispatched, NOT push-triggered)

The Hub image is NOT built on push to main. The orchestrating chat dispatches
the build workflow (see Phase 5 in the report):

- Workflow: `.github/workflows/build-images.yml` (workflow_dispatch).
- Inputs: `target=hub`, `registry=ghcr.io/lumeniqjs`, `tag=<chosen tag>`,
  `platform=all` (or `linux/amd64`).
- Produces image: `ghcr.io/lumeniqjs/scion-hub:<tag>`.
- NOTE: the `hub` target builds FROM `ghcr.io/lumeniqjs/scion-base:<tag>`. Ensure
  a matching `scion-base:<tag>` exists in the registry, or dispatch `target=common`
  (scion-base + harnesses + hub) so the base is rebuilt first.

Dispatch via MCP:

```
mc_github_dispatch_workflow(owner=lumeniqjs, repo=scion,
  workflow_id=build-images.yml, ref=main,
  inputs={ target: "hub", registry: "ghcr.io/lumeniqjs", tag: "<tag>", platform: "all" })
```

Record the run id and confirm it is green before proceeding.

## Step 1 -- Pull the new Hub image on the VM

```bash
gcloud compute ssh scion-substrate-01 --zone us-east1-b
# on the VM:
docker pull ghcr.io/lumeniqjs/scion-hub:<tag>
```

(Confirm the exact image ref the VM's Hub service is configured to run; if it
pins a digest or a different tag, update the service unit / compose accordingly.)

## Step 2 -- Set Hub config for audience + allowlist (ENABLE the feature)

Set these in the Hub service environment (systemd drop-in / compose env /
whatever the VM uses), then they take effect on restart:

```bash
SCION_SERVER_GCP_IDENTITY_ENABLED=true
SCION_SERVER_GCP_IDENTITY_AUDIENCE=https://scion-hub.lumeniq.ai
```

- The trusted-SA allowlist is built in (code-defined seed); no extra env needed
  for the mc-cloud-run-invoker entry.
- Leaving `SCION_SERVER_GCP_IDENTITY_ENABLED` unset (or != "true") keeps the
  feature OFF -- safe rollback is simply unsetting it and restarting.

## Step 3 -- Restart the Hub and confirm healthy

```bash
sudo systemctl restart scion-hub     # or the VM's restart mechanism
sudo systemctl status scion-hub
# Confirm the startup log line:
#   "Inbound GCP workload-identity auth enabled" audience=... allowlist_size=1
curl -fsS https://scion-hub.lumeniq.ai/healthz && echo OK
```

If the log says "NOT configured (feature off)", the env did not take -- re-check
Step 2.

## Step 4 -- Verification probe (auth passes; expect 400, NOT 401)

Mint a GCP ID token for the dispatcher SA with the pinned audience and POST to a
protected endpoint. A request that PASSES authentication should fail on request
BODY validation (HTTP 400) or authorization, NOT on auth (HTTP 401).

```bash
TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account=mc-cloud-run-invoker@lumeniq-saas-factory.iam.gserviceaccount.com \
  --audiences=https://scion-hub.lumeniq.ai)

# Empty body on a protected create endpoint:
curl -i -X POST https://scion-hub.lumeniq.ai/api/v1/agents \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Interpreting the result:

- **HTTP 400 / 403 (validation or authorization error)** -> SUCCESS. The token
  authenticated; the SA principal reached the handler.
- **HTTP 401 "invalid GCP identity token"** -> the token failed verification.
  Common causes: audience mismatch (token `--audiences` != Hub
  `SCION_SERVER_GCP_IDENTITY_AUDIENCE`), SA not in the allowlist, or the
  impersonation produced a token for the wrong SA email.
- **HTTP 401 "unrecognized token format" / "invalid access token"** -> the
  feature is not enabled on this Hub (Step 2/3), so the Google token fell
  through to the user-JWT path.

NOTE on authorization: this spec delivers the AUTHENTICATION path only. The SA
principal is project+scope scoped (like a PAT) but, lacking a backing user with
ownership/group membership, it will be DENIED by policy on actions that require
an explicit grant. Granting the `gcp-sa:<email>` principal the policies it needs
(or enrolling it in the project's members group) is a follow-up, separate from
landing authentication. The probe above only verifies authentication.

## Rollback

Unset `SCION_SERVER_GCP_IDENTITY_ENABLED` (or set it to anything other than
`true`) and restart the Hub. The GCP identity path goes dark again; all other
auth paths are unaffected.
