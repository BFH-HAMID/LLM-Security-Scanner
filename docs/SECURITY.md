# Security

Two audiences: people **running** llmscan (how to deploy it safely) and people who **found a problem**
in it (how to tell us). For what you are allowed to *scan*, read [ETHICS.md](ETHICS.md).

## Reporting a vulnerability in llmscan

Please do **not** open a public issue for a security problem.

1. Use GitHub's private reporting: **Security → Report a vulnerability** on
   <https://github.com/BFH-HAMID/LLM-Security-Scanner>
   (direct link: `/security/advisories/new`).
2. Include what you found, how to reproduce it, the version or commit, and what an attacker gains.

What to expect from a small open-source project (best effort, not a contract):

- an acknowledgement within **7 days**;
- a fix or a mitigation plan within **90 days**, sooner for anything actively exploitable;
- credit in the release notes if you want it, and a coordinated release date agreed with you;
- no legal action against good-faith research that follows this policy and stays inside your own
  installation.

Highest-value reports: anything that lets an API or dashboard user read secrets they should not, reach
hosts the operator restricted, execute code on the server, escape the report HTML sandbox, or bypass
authentication.

## Threat model

llmscan is a tool that **connects out to targets you name** and **stores what they answer**. That gives it
three assets worth protecting:

1. **Credentials** you give it: target API keys and tokens, and the scanner's own API keys.
2. **Reachability**: a server that can be told to send requests anywhere is an SSRF gadget.
3. **Reports**: a successful leak probe means the transcript contains the leaked secret or PII.

Untrusted inputs: everything a target returns (it may be hostile: transcripts are rendered in HTML and
in the dashboard), third-party probe files, and, on a shared server, other API users.

## What is built in

| Area | Control | Where |
|---|---|---|
| Authentication | Every API route needs an API key (`X-API-Key` or `Authorization: Bearer`) except `/health` and the interactive docs (`/docs`, `/openapi.json`, which describe the API but expose no data; turn them off with `LLMSCAN_DOCS_ENABLED=false`). Keys are stored only as SHA-256 hashes and shown once. `LLMSCAN_AUTH_DISABLED` exists for local development only. | `api/deps.py`, `scanner/storage` |
| Tenant isolation | Targets, runs and results belong to a project; a project key cannot read another project's data. Admin keys manage projects and keys. | `api/routers/*` |
| Secret masking | Secrets in target configs are masked in every API response and in the dashboard; sending the masked value back on update keeps the stored secret. | `api/masking.py` |
| **Environment leakage** | A stored target config may **not** contain `${VAR}` references unless the operator names the variable in `LLMSCAN_ENV_ALLOWLIST`, and the worker can only see that list. Provider shorthands (`openai:MODEL@URL`) for the judge and attacker resolve against the same restricted environment. Without this, any API user could aim a target at their own server and receive the server's secrets. | `api/routers/targets.py`, `api/jobs/runner.py` |
| SSRF hardening | `LLMSCAN_TARGET_ALLOWLIST` (fnmatch host patterns) and `LLMSCAN_BLOCK_PRIVATE_TARGETS` apply to targets **and** to judge / attacker models, including string shorthands. | `api/routers/targets.py`, `api/routers/runs.py` |
| No server files | `probe_paths` and `builtin_probes` are rejected over the API, so a caller cannot make the server read arbitrary files as probes. Reports contain repository-relative paths only. | `api/routers/runs.py` |
| Bounded work | `LLMSCAN_MAX_ATTEMPTS` (default 20 000 per run) and `LLMSCAN_MAX_CONCURRENCY` (default 16). | `api/settings.py` |
| Report safety | The HTML report is self-contained, escapes every value (transcripts are attacker-controlled), loads nothing remote, and is served as an attachment with `Content-Security-Policy: default-src 'none'`. | `scanner/reporting/html.py` |
| API headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`; CORS is off unless `LLMSCAN_CORS_ORIGINS` is set. | `api/main.py` |
| Probe templates | Probes use a tiny substitution engine, not Jinja: a probe file cannot execute code. | `scanner/templating.py` |
| Containers | Images run as an unprivileged user, secrets come from the environment (never baked in), and Compose publishes every port on `127.0.0.1` by default. | `docker/`, `docker-compose.yml` |

### The dashboard

The dashboard holds an API key and can start scans, so it is treated as a privileged component:

- The key lives only on the dashboard **server** (`LLMSCAN_API_KEY`); the browser talks to a same-origin
  proxy at `/api/llmscan/*` that attaches it. It never appears in a page, script or response.
- The proxy forwards only the endpoints the UI uses (`runs`, `targets`, `compare`, `probes`, `meta`, `me`,
  `health`), **not** key or project administration, and rejects path traversal.
- State-changing requests must be same-origin (`Sec-Fetch-Site` / `Origin` check), which blocks
  cross-site request forgery from any web page the operator visits.
- Set `DASHBOARD_PASSWORD` to require HTTP Basic authentication for every page and API call
  (`DASHBOARD_USER`, default `admin`). Compose binds the dashboard to `127.0.0.1`; if you change
  `BIND_ADDR`, set a password or put an authenticating reverse proxy in front.
- Give the dashboard a **project** key rather than an admin key: even a compromised dashboard then
  cannot mint keys.

## Deploying safely

1. Generate strong secrets (`make env` does) and keep `.env` out of version control.
2. Leave `BIND_ADDR=127.0.0.1` unless you have TLS and authentication in front.
3. On a shared or hosted server set `LLMSCAN_TARGET_ALLOWLIST` to the hosts people may scan and consider
   `LLMSCAN_BLOCK_PRIVATE_TARGETS=true`, so the scanner cannot be used to poke at your own network.
4. Leave `LLMSCAN_ENV_ALLOWLIST` empty unless you need server-managed provider keys. Anything listed
   there can be sent to whatever host a target points at, so combine it with the target allowlist.
5. Never expose the demo target (`target` in Compose) to a network. It is deliberately vulnerable.
6. Back up and protect the database: see the limitations below.

## Known limitations

- **Secrets are stored in plaintext in the database.** They are masked in responses, but anyone with
  database access can read them. Encrypt the volume, restrict access, and prefer short-lived keys.
  (Application-level encryption at rest is not implemented.)
- **Transcripts contain what leaked.** That is the point of a leak finding. Use canaries and fake data,
  `--redact`, and retention limits.
- **API keys have no expiry or scopes** beyond project membership and admin. Rotate them by revoking and
  creating new ones.
- **The built-in rate limit is per run**, not per key or per tenant. Put a gateway in front of a
  multi-tenant deployment.
- **A target you are authorised to scan can still be dangerous to scan**: see the side-effects section of
  [ETHICS.md](ETHICS.md).
- Dependency and image scanning are not part of CI yet. Run your own scanner over the images.

## Security regression tests

The fixes above are covered by tests that were checked to fail when the fix is removed:
`tests/test_api_secrets.py` (environment leakage and nested-target policy), `tests/test_api.py`
(authentication, isolation, masking, CSP), `tests/test_reporting.py` (HTML escaping) and
`tests/test_compose.py` (ports, secrets, non-root images).
