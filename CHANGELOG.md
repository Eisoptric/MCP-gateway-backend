# Changelog

Notable changes to MCP Gateway Backend. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Saturn MCP is now MCP Gateway, by Eisoptric.** The repository moved to [eisoptric/MCP-gateway-backend](https://github.com/eisoptric/MCP-gateway-backend), and the public addresses to `api.eisoptric.com`, `ws.eisoptric.com` and `console.eisoptric.com`.
- **Breaking: nothing signed or sealed before this version opens after it.** Every domain-separation label changed from `saturn-*` to `eisoptric-*` (login and member-wrap derivation, payload keys, credential encryption, approval digests, TOTP backups, recovery keys), so existing passwords, sealed credentials, wrapped member keys and webhook signatures from earlier versions no longer verify. Deploy it to a fresh database, or plan a re-enrolment.
- `infra/gcp/move-project.sh` builds the deployment in a new Google Cloud project (`eisoptric-prod`) and copies the secrets that still hold from the old one, renamed from `SATURN_` to `GATEWAY_`. The database and Redis start empty.
- **No load balancer.** On Cloudflare's free plan the API deploys with ingress `all` behind the origin secret Cloudflare adds. `infra/gcp/cloudflare-ingress.sh` and the `CLOUD_RUN_INGRESS` variable are gone, and the deploy no longer warns about ingress.
- Settings are read from `GATEWAY_*` (was `SATURN_*`, for example `GATEWAY_KMS_KEY`, `GATEWAY_GOOGLE_OAUTH_CLIENT_ID`), headers are `X-Eisoptric-*` and `Eisoptric-Webhook-*`, the cookies are `eisoptric_session` and `eisoptric_oauth`, the OAuth scope is `eisoptric.mcp`, and an agent resubmits an approved call with `gatewayRunId` (was `saturnRunId`). The default organization id is `org_default` (was `org_saturn`): an existing deployment sets `DEFAULT_ORG_ID=org_saturn` to keep its organization.

### Added

- Organization admins approve their own MCP hosts at `/mcp-servers/allowed-hosts`, beside Eisoptric's `ALLOWED_MCP_HOSTS`. Custom servers on those hosts can now be connected; before, any host outside Eisoptric's list was refused. Approving a host needs a recent sign-in, and the change is recorded. A removed host stops calls at once. Migration `067_mcp_allowed_hosts` adds the table.
- At most 256 upstream HTTP clients are kept, one per host. The least recently used one is closed 180 seconds after it is retired, so a call still using it can finish.

- `mcp.cloudflare.com`, `run.googleapis.com`, `redis.googleapis.com`, `sqladmin.googleapis.com` (Cloud SQL), `api.alphaxiv.org` and `mcp.withwandb.com` are approved MCP hosts. Google sign-in may now ask for `auth/run`, `auth/redis.read-write` and `auth/cloudsql`, the one scope each of those servers advertises; `cloud-platform` is still never requested.

### Fixed

- A mistyped code on the agent sign-in page (`/oauth/login/code`) ended the sign-in with "That code is incorrect or expired", with no field to try again, so one typo meant starting over for a new code. The page now shows the form again with the same challenge and a message, while the challenge still has guesses left (5 per code, as before). It ends the sign-in only once the code is used up or expired, and then says to start again. The console's sign-in already kept the form.
- An MCP server's refusal read only "MCP server returned HTTP 403" (or another status), so a disabled Google MCP service, a missing permission and a server's own rule looked the same. The message now ends with the server's reason, with credentials removed and cut to 200 characters. Two Google refusals get a fixed sentence, because Google's text names the operator's Google Cloud project: the MCP service is not enabled, or the sign-in did not grant the needed access. The full answer, without credentials, is logged as a warning.
- Drafting or optimizing a policy with the model failed with only "Policy model request failed", and nothing was logged, so a wrong key, model name or URL looked the same. The message now names the cause by the provider's status (key rejected, endpoint or model not found, rate limited or out of credit, request rejected, provider error, timeout, unreachable). The provider's response, with the key removed, is logged as a warning. It is never shown in the console.
- Signing in to connect an agent failed on iOS with "Start again from the agent to sign in". The sign-in pages send `Referrer-Policy: no-referrer`, so WebKit posts their forms with `Origin: null`, which the cross-site check refused. A null origin is now accepted when `Sec-Fetch-Site` is `same-origin`; with any other value, or none, it is still refused.
- The OAuth sign-in fields use 16px text, so iOS no longer zooms into them.
- Sixteen marketplace servers could not be connected because their hosts were missing from `ALLOWED_MCP_HOSTS`: Google Sheets, Docs, Slides and Drive, Canva, Figma, Adobe, Microsoft 365, Etherscan, Vercel, Indeed, Spotify, Booking.com, Sumsub, Northwest Registered Agent and Plaid. Their hosts are added, and so is `mcp.slack.com`, Slack's fixed MCP endpoint.

### Changed

- pydantic 2.14.2 to 2.14.3 (with pydantic-core 2.50.4) and SQLAlchemy 2.1.6 to 2.1.8. The locks are regenerated with `uv pip compile` and `--exclude-newer 2026-11-06`, as `requirements.in` describes, and the older per-package exceptions are dropped, since that date covers them. This replaces Dependabot's #29 and #26, whose locks were made another way: they dropped platform markers (uvloop on Windows) and added gRPC extras.
- The organization's default policy can be deleted. Before, deleting it was refused with "Change its rules or pause it instead". Once it is gone, a tool no policy has a rule for follows the agent's tool set, and connecting a server does not recreate it. Its description stays reserved, so no other policy can pass for it.
- Gmail sign-in asks for `gmail.modify` instead of `gmail.readonly` and `gmail.compose`. Google's Gmail MCP server has tools to label, trash and mark mail as spam, which the narrower scopes did not allow. `gmail.modify` also covers reading and drafts, and cannot delete mail permanently. Full `mail.google.com` is never requested. Connections signed in before this keep their old grant until they sign in again.
- Google Calendar sign-in asks for `calendar.events` instead of `calendar.events.readonly`, beside `calendar.calendarlist.readonly` and `calendar.events.freebusy`. Google's Calendar MCP server creates, updates and deletes events and answers invitations. Full `calendar`, which also manages calendars and sharing, is not requested.
- When no policy has a rule for a tool, the agent's tool set now decides: the call waits for approval if the tool's item is marked for approval, and runs otherwise. Before, such a call was denied (with `POLICY_DEFAULT_DENY=true`, the default). A tool that has rules but no matching rule is still denied, and so is a tool outside the agent's tool set. The decision reason names the tool set. The tool set is read on every call, so a change applies to the next call and to the check before an approved call runs. The startup report of agents without a policy now leaves out agents with a tool set.
- A tool set item now requires approval unless it says otherwise (`approval` defaults to `true` in the API and the model). With no policy rule, that setting decides the call, so a tool added without a setting waits for a person. Existing items keep their value. An API client that sends an item without `approval` now gets approval, including for an item that was set to allow.
- Eisoptric's Google OAuth app now asks each Google MCP host only for its own scopes (`_GOOGLE_SCOPES` maps host to scopes). Before, one shared list was matched against whatever a server advertised, so any Google server listing another one's scope got it too. Sheets, Docs and Slides get `spreadsheets`, `documents` and `presentations`; Drive gets `drive.readonly` and `drive.file`, never full `drive`. A Google host with no entry, including one an organization approved, gets no scope.
- The outside uptime check moved from a scheduled GitHub workflow to Cloud Monitoring, created by `infra/gcp/uptime-checks.sh`, with an email alert. On the Cloudflare free plan, Bot Fight Mode answered every run from GitHub with a 403 while the API was up.

## [0.1.0] - 2026-11-16

This is the first tagged release, and it ends the first phase of development. The gaps that are known and not yet fixed are listed under [Known limitations](README.md#known-limitations) in the README.

### What it includes

- **MCP gateway.** Agents connect to one MCP endpoint and sign in with OAuth. Each agent sees only its assigned tools. Eisoptric holds the upstream credentials and OAuth tokens in an ML-KEM-1024 vault whose root key stays in Cloud KMS.
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

- [#38](https://github.com/eisoptric/MCP-gateway-backend/pull/38) Drop the audit source trigger, finish auth and gateway follow-ups
- [#37](https://github.com/eisoptric/MCP-gateway-backend/pull/37) Fix the known issues: gateway races, upstream sessions, sign-in, policies, activity paging
- [#36](https://github.com/eisoptric/MCP-gateway-backend/pull/36) Set GOOGLE_CLOUD_PROJECT so request logs carry their trace
- [#35](https://github.com/eisoptric/MCP-gateway-backend/pull/35) Keep approvals a KMS outage stopped, settle stuck claims, and check uptime for free
- [#34](https://github.com/eisoptric/MCP-gateway-backend/pull/34) Review follow-ups, /health and /status, and a domain model for approvals
- [#33](https://github.com/eisoptric/MCP-gateway-backend/pull/33) Follow the rename to MCP-gateway-backend and MCP-gateway-frontend
- [#32](https://github.com/eisoptric/MCP-gateway-backend/pull/32) Close fail-open paths in policy and approvals, bound resources, and add logging, CI checks and upgrades
- [#31](https://github.com/eisoptric/MCP-gateway-backend/pull/31) Filter and page the admin audit and usage views; report TOTP in the MFA status
- [#30](https://github.com/eisoptric/MCP-gateway-backend/pull/30) Bump pytest-asyncio from 1.4.1 to 1.4.1.post1
- [#24](https://github.com/eisoptric/MCP-gateway-backend/pull/24) Bump four Python packages and the GitHub Actions group
- [#23](https://github.com/eisoptric/MCP-gateway-backend/pull/23) Let admins meet the MFA requirement with a passkey or TOTP
- [#22](https://github.com/eisoptric/MCP-gateway-backend/pull/22) Fix findings from the 2026-11-08 security review
- [#18](https://github.com/eisoptric/MCP-gateway-backend/pull/18) Tech debt: shared limits, key cache, legacy password deadline
- [#17](https://github.com/eisoptric/MCP-gateway-backend/pull/17) Structured errors for denied and pending tool calls
- [#16](https://github.com/eisoptric/MCP-gateway-backend/pull/16) Require TOTP for organization admins
- [#15](https://github.com/eisoptric/MCP-gateway-backend/pull/15) Mark pq1 secrets as needing reconnect
- [#14](https://github.com/eisoptric/MCP-gateway-backend/pull/14) Block direct Cloud Run access
- [#13](https://github.com/eisoptric/MCP-gateway-backend/pull/13) Block deploy until tests pass
- [#12](https://github.com/eisoptric/MCP-gateway-backend/pull/12) Default deny when no policy applies
- [#1](https://github.com/eisoptric/MCP-gateway-backend/pull/1) Require GATEWAY_KEM_SEED and accept the split login verifier

[0.1.0]: https://github.com/eisoptric/MCP-gateway-backend/releases/tag/v0.1.0
