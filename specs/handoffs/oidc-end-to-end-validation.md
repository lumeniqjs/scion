# OIDC end-to-end validation -- mc-api -> scion-hub

- Validated at: 2026-05-29T02:19:24Z
- Agent: 8b1698fc1fe7
- Hub auth path: GCP workload-identity (S435 + authz grant 017dd441)
- mc-api client mode: MC_SCION_CLIENT_AUTH_MODE=oidc (d77e5a59)

The arrival of this commit proves the OIDC dispatch path is live end-to-end:
mc-api scion-client minted a Google ID token (audience https://scion-hub.lumeniq.ai),
presented it as Bearer to the Hub, the Hub validated it against the GCP-identity
allowlist + authz grant for project 3152156d-67ef-415f-8ca5-903b446e2894, and
authorized the agent:create. PAT retirement is unblocked.
