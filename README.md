# Agentic Alert Triage

A GitHub App built with [Probot](https://probot.github.io/) that reviews
delegated security alert dismissal requests across an enterprise.
It supports deterministic policy checks, bounded agentic
review, or both.

| Mode | Behavior |
|---|---|
| `deterministic` | Immediately deny requests whose comments fail configured phrase, pattern, or length checks. Passing requests remain open. |
| `agentic` | Send every created request to the central gh-aw workflow for contextual review. |
| `both` | Deny deterministic failures immediately and dispatch passing requests for agentic review. |

> [!IMPORTANT]
> The agent never approves a dismissal request. A request judged as "ready" remains
open and the alert is assigned to the configured AppSec team for final human
review.

## How it works

1. **A requester asks to dismiss an alert.** The App responds to newly created
   delegated dismissal requests for code scanning, Dependabot, and secret
   scanning alerts.

2. **The configured review mode determines the checks.**
   - Deterministic review checks whether the request comment meets configured
     phrase, pattern, and minimum-length requirements. Requests that fail are
     denied immediately.
   - Agentic review evaluates whether the dismissal reason is clear and
     relevant, the justification explains why dismissal is appropriate, and
     the supporting evidence is concrete, verifiable, and consistent with the
     alert.
   - `both` applies the deterministic requirements first, then sends passing
     requests through agentic review.

3. **The request is routed to the next outcome.**
   - `ready_for_review`: the request remains open and the alert is assigned to
     the enterprise AppSec team for a final human decision.
   - `deny`: the request is denied with an explanation of what is missing or
     inconsistent and what the requester should provide next.

   Existing code scanning and Dependabot assignees are preserved. Secret
   scanning supports one AppSec assignee, selected consistently from the team.

Requester comments, alert fields, and linked issue content are treated as
untrusted evidence, never as instructions. Secrets and credentials are excluded
or redacted, and ambiguous requests are denied rather than guessed.

## Setup

> [!TIP]
> Try opening this repository in the [GitHub Copilot App](https://github.com/github/app) and prompting Copilot in `Interactive` mode like this:
> > "Guide me through step by step setup of this app in my enterprise `YOUR_ENTERPRISE_SLUG` where I'll be installing the app in `YOUR_ORG_SLUGS` orgs.

### 1. Meet the prerequisites

- Node.js 22 or newer. GitHub Actions may use Node.js 24.
- One
  [GitHub App owned by the enterprise](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-github-apps-for-your-enterprise/creating-github-apps-for-your-enterprise).
  Enterprise-owned Apps have internal visibility and can be installed only
  within that enterprise.
- A central workflow repository in an organization inside the same enterprise.
- One nonempty enterprise team, such as `ent:appsec-team`, with the
  [**enterprise Security Manager role**](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-accounts-and-repositories/managing-roles-in-your-enterprise/assign-roles).
- Delegated alert dismissal enabled in every monitored organization.

### 2. Register and configure the GitHub App

[`app.yml`](app.yml) is the Probot manifest for initial registration. Changing
it does not update an existing App, so verify existing registrations in the
GitHub App settings UI.

Configure these permissions:

| Scope | Permission shown in GitHub | Access | Purpose |
|---|---|---|---|
| Enterprise | Enterprise teams | Read-only | Read the configured enterprise team's members |
| Organization | Organization dismissal requests for code scanning | Read & write | Receive and review code scanning requests |
| Organization | Organization dismissal requests for Dependabot | Read & write | Receive and review Dependabot requests |
| Organization | Secret scanning alert dismissal requests | Read & write | Receive and review secret scanning requests |
| Repository | Code scanning alerts | Read & write | Read alerts and assign ready alerts |
| Repository | Dependabot alerts | Read & write | Read alerts and assign ready alerts |
| Repository | Secret scanning alerts | Read & write | Read hidden-secret context and assign ready alerts |
| Repository | Contents | Write | Create `repository_dispatch` in the control repository |
| Repository | Issues | Read-only | Read bounded linked evidence |
| Repository | Metadata | Read-only | Access required repository metadata |

Configure these webhook subscriptions:

- Dismissal request for code scanning
- Dismissal request for Dependabot
- Dismissal request for secret scanning

Set the webhook secret to the same strong value used by the Probot service.

### 3. Install the App

Install the same App in three scopes:

1. **Enterprise account:** provides enterprise team membership access.
2. **Monitored organizations and repositories:** receives webhooks, performs
   denials, and reads or assigns alerts. Include repositories used for linked
   issue evidence.
3. **Control repository:** permits `repository_dispatch` and runs the agentic
   workflow.

> [!IMPORTANT]
> The enterprise installation does not replace organization or repository
> installations, and organization installations do not replace the enterprise
> installation. The incoming webhook token is never assumed to access the
> enterprise team API or control repository.

After initial setup, onboarding another organization requires only installing
the App, selecting the monitored repositories, and enabling delegated
dismissal. No separate AppSec team is needed.

### 4. Configure the service and workflow

[`config.yml`](config.yml) is loaded once when Probot starts. Keep the service
and control repository copies aligned:

```yaml
enterprise: your-enterprise
review_mode: both

required_pattern: "https://github\\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9._-]+/issues/\\d+"
minimum_length: 20
case_sensitive: false

alert_types:
  - code_scanning
  - dependabot
  - secret_scanning

agentic:
  workflow_repository: your-security-org/alert-triage
  model: auto
  appsec_team_slug: ent:appsec-team
  staged: true

cache:
  app_identity_ttl_seconds: 600
  enterprise_installation_ttl_seconds: 600
  team_members_ttl_seconds: 300
  control_installation_ttl_seconds: 600
  delivery_dedupe_ttl_seconds: 900
  delivery_dedupe_max_entries: 1000
```

`enterprise` is required in every mode. The target organization always comes
from the validated webhook snapshot, never the control repository owner or
`GITHUB_REPOSITORY`.

| Key | Default | Description |
|---|---|---|
| `enterprise` | required | Enterprise URL slug that must own the App |
| `review_mode` | `both` | `deterministic`, `agentic`, or `both` |
| `required_phrase` | none | Phrase required in the requester comment |
| `required_pattern` | none | JavaScript regular expression required in the requester comment |
| `minimum_length` | none | Minimum trimmed requester-comment length |
| `case_sensitive` | `false` | Case-sensitive phrase and regex matching |
| `alert_types` | all three | Enabled alert categories |
| `agentic.workflow_repository` | Required | Central repository that runs the agentic workflows |
| `agentic.model` | `auto` | Copilot model used by the agentic workflow |
| `agentic.appsec_team_slug` | `ent:appsec-team` | Enterprise team with the Security Manager role; `ent:` is required |
| `agentic.staged` | `true` | Preview SafeOutput writes |
| `agentic.help_contact` | `Enterprise AppSec team in your alert (@/ent:appsec-team)` | Contact text included in agentic denials |
| `agentic.denial_message` | built-in | Optional agentic denial template |
| `denial_message` | built-in | Optional deterministic denial template |
| `cache.app_identity_ttl_seconds` | `600` | App ownership cache TTL, 1-3600 seconds |
| `cache.enterprise_installation_ttl_seconds` | `600` | Enterprise installation cache TTL, 1-3600 seconds |
| `cache.team_members_ttl_seconds` | `300` | Enterprise team membership cache TTL, 1-3600 seconds |
| `cache.control_installation_ttl_seconds` | `600` | Control installation cache TTL, 1-3600 seconds |
| `cache.delivery_dedupe_ttl_seconds` | `900` | Successful operation dedupe TTL, 1-3600 seconds |
| `cache.delivery_dedupe_max_entries` | `1000` | Delivery cache size, 1-10000 |

Agentic denial placeholders are `{requester}`, `{denial_reason}`,
`{help_contact}`, `{alert_type}`, `{alert_number}`, and `{repo_full_name}`.
Deterministic denial placeholders are `{alert_type}`, `{alert_number}`,
`{required_phrase}`, `{denial_reason}`, `{requester}`, and `{repo_full_name}`.

Denial request responses are rendered as plain text by GitHub. The built-in
agentic denial uses the validated enterprise-team mention
`@/ent:appsec-team`; untrusted agent rationale has mentions neutralized. Use
labels and plain URLs instead of other Markdown in denial templates. Avoid
organization-specific names in shared regexes and denial templates. The
agentic workflow reads linked evidence only from the target organization.

### 5. Configure credentials

Set these values for the persistent Probot service:

| Variable | Required | Description |
|---|---:|---|
| `APP_ID` | yes | GitHub App ID |
| `PRIVATE_KEY` or `PRIVATE_KEY_PATH` | yes | GitHub App private key contents or file path |
| `WEBHOOK_SECRET` | yes | Secret matching the GitHub App webhook configuration |
| `PORT` | no | HTTP port, default `3000` |
| `WEBHOOK_PROXY_URL` | local only | Smee or equivalent forwarding URL |
| `CONFIG_PATH` | no | Configuration path, default `./config.yml` |
| `LOG_LEVEL` | no | Probot log level |

Set these Actions secrets in the control repository:

| Secret | Description |
|---|---|
| `ALERT_DISMISSAL_APP_CLIENT_ID` | Client ID for the same GitHub App |
| `ALERT_DISMISSAL_APP_PRIVATE_KEY` | Full private key PEM for that App |

Set this Actions variable in the control repository:

| Variable | Description |
|---|---|
| `ALERT_DISMISSAL_APP_BOT` | Exact bot login for the same App, such as `agentic-alert-triage[bot]`; gh-aw uses it as the only bot allowed to activate the dispatch workflow |

Workflow jobs authenticate as the App before selecting the target organization.
The model never receives App credentials or installation tokens. Copilot
inference uses `copilot-requests: write` on the workflow's built-in Actions
token.

## Deploy

Set the GitHub App webhook URL to the public Probot endpoint:

```text
https://your-service.example/api/github/webhooks
```

Probot validates `X-Hub-Signature-256` with `WEBHOOK_SECRET`; do not deploy
without it.

Install dependencies and start the persistent service:

```bash
npm install
npm start
```

The platform-neutral [`Dockerfile`](Dockerfile) uses Node.js 22:

```bash
docker build -t agentic-alert-triage .
docker run --rm -p 3000:3000 --env-file .env agentic-alert-triage
```

Mount the private key file when using `PRIVATE_KEY_PATH`, or provide
`PRIVATE_KEY` through the deployment secret store.

For multiple replicas, Probot can use `REDIS_URL` for Octokit rate-limit
coordination. Delivery deduplication remains process-local; use an external
queue or idempotency store if the deployment requires durable exactly-once
processing.

See Probot's
[configuration](https://probot.github.io/docs/configuration/) and
[deployment](https://probot.github.io/docs/deployment/) guides.

## Development

### Compile and stage the workflow

The generated
[`agentic-dismissal-review.lock.yml`](.github/workflows/agentic-dismissal-review.lock.yml)
comes from
[`agentic-dismissal-review.md`](.github/workflows/agentic-dismissal-review.md).
Never edit the lock file directly.

```bash
npm install
npm run compile:agentic
```

Commit both workflow files and deploy them to the control repository's default
branch. Keep `agentic.staged: true` while reviewing workflow summaries and
gh-aw audit logs. Set it to `false` only when decisions are ready to write.
Restart Probot after configuration changes.

For local webhook development:

```bash
cp .env.example .env
# Fill APP_ID, PRIVATE_KEY_PATH, WEBHOOK_SECRET, and WEBHOOK_PROXY_URL.
npm install
npm run dev
```

Create a temporary forwarding URL at [smee.io](https://smee.io/new), use it for
both the App webhook URL and `WEBHOOK_PROXY_URL`, and keep its secret identical
to `WEBHOOK_SECRET`.

Run the repository checks:

```bash
npm run check
npm test
npm run compile:agentic
```

The tests cover webhook routing and validation, deterministic and agentic
review modes, snapshot redaction, installation and membership caching,
dispatch authentication, retries and stale writes, secret hiding, assignment,
failure propagation, enterprise ownership, cross-organization isolation,
token-owner validation, and installation-ID mismatches.
