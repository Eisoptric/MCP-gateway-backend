# Changelog

Notable changes to Saturn Backend. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Organization admins approve their own MCP hosts at `/mcp-servers/allowed-hosts`, beside Saturn's `ALLOWED_MCP_HOSTS`. Custom servers on those hosts can now be connected; before, any host outside Saturn's list was refused. Approving a host needs a recent sign-in, and the change is recorded. A removed host stops calls at once. Migration `067_mcp_allowed_hosts` adds the table.
- At most 256 upstream HTTP clients are kept, one per host. The least recently used one is closed 180 seconds after it is retired, so a call still using it can finish.

- `mcp.cloudflare.com`, `run.googleapis.com`, `redis.googleapis.com`, `sqladmin.googleapis.com` (Cloud SQL), `api.alphaxiv.org` and `mcp.withwandb.com` are approved MCP hosts. Google sign-in may now ask for `auth/run`, `auth/redis.read-write` and `auth/cloudsql`, the one scope each of those servers advertises; `cloud-platform` is still never requested.

### Changed

- The outside uptime check moved from a scheduled GitHub workflow to Cloud Monitoring, created by `infra/gcp/uptime-checks.sh`, with an email alert. On the Cloudflare free plan, Bot Fight Mode answered every run from GitHub with a 403 while the API was up.

## [0.1.0] - 2026-11-16

This is the first tagged release, and it ends the first phase of development. The gaps that are known and not yet fixed are listed under [Known limitations](README.md#known-limitations) in the README.

### What it includes

- **MCP gateway.** Agents connect to one MCP endpoint and sign in with OAuth. Each agent sees only its assigned tools. Saturn holds the upstream credentials and OAuth tokens in an ML-KEM-1024 vault whose root key stays in Cloud KMS.
- **Policies and approvals.** A policy decides every tool call, and a call with no matching policy is denied. Calls can be held for a person's approval, and the approval is bound to the exact arguments.
- **Audit.** Tool arguments and upstream results are encrypted to the organization's key and to the keys of approved members. Changes to policies, tool sets, members and agents are recorded too.
- **Accounts.**
  - The password verifier is derived in the browser with Argon2id.
  - Passkeys, TOTP and emailed codes.
  - Step-up for sensitive changes.
  - Admins must have a passkey or TOTP.
- **Operations.**
  - `/health`, and `/status` with 90-day availability.
  - Structured request logs that carry a trace.
  - A scheduled uptime check.
  - Deploys run tests first and wait for approval in the `production` environment.
- **License.** Apache 2.0. Earlier commits were licensed under FSL-1.1-ALv2.

### Pull requests

- [#38](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/38) Drop the audit source trigger, finish auth and gateway follow-ups
- [#37](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/37) Fix the known issues: gateway races, upstream sessions, sign-in, policies, activity paging
- [#36](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/36) Set GOOGLE_CLOUD_PROJECT so request logs carry their trace
- [#35](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/35) Keep approvals a KMS outage stopped, settle stuck claims, and check uptime for free
- [#34](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/34) Review follow-ups, /health and /status, and a domain model for approvals
- [#33](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/33) Follow the rename to Saturn-MCP-Backend and Saturn-MCP-Frontend
- [#32](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/32) Close fail-open paths in policy and approvals, bound resources, and add logging, CI checks and upgrades
- [#31](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/31) Filter and page the admin audit and usage views; report TOTP in the MFA status
- [#30](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/30) Bump pytest-asyncio from 1.4.1 to 1.4.1.post1
- [#24](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/24) Bump four Python packages and the GitHub Actions group
- [#23](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/23) Let admins meet the MFA requirement with a passkey or TOTP
- [#22](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/22) Fix findings from the 2026-11-08 security review
- [#18](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/18) Tech debt: shared limits, key cache, legacy password deadline
- [#17](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/17) Structured errors for denied and pending tool calls
- [#16](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/16) Require TOTP for organization admins
- [#15](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/15) Mark pq1 secrets as needing reconnect
- [#14](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/14) Block direct Cloud Run access
- [#13](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/13) Block deploy until tests pass
- [#12](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/12) Default deny when no policy applies
- [#1](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/pull/1) Require SATURN_KEM_SEED and accept the split login verifier

[0.1.0]: https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/releases/tag/v0.1.0
