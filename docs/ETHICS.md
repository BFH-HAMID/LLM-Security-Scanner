# Ethics and scope policy

llmscan sends attack payloads to AI applications. That is exactly what a defender needs, and exactly
what an abuser could do, so this page is the contract for using it.

## The rule

**Only scan systems you own, or that you have explicit, written permission to test.**

"Explicit permission" means one of:

- you operate the system (your own staging or test deployment);
- you are an employee or contractor and testing it is part of your assignment;
- the owner has authorised it in writing (a scope document, a penetration-test statement of work);
- the owner runs a bug-bounty or vulnerability-disclosure programme and the target and technique are
  in scope.

Curiosity, "it is publicly reachable", or "they will not notice" are not permission. Unauthorised
access to a computer system is a crime in most jurisdictions, and this is true even when the "attack" is
only a chat message.

Third-party model APIs (OpenAI, Anthropic and others) have their own usage policies. Testing *your own*
application's prompts against a provider using *your own* account is normal; using llmscan to probe a
provider's platform itself is not something this project supports.

This document is guidance, not legal advice.

## What llmscan does to keep you on the right side of that rule

| Guard | Behaviour |
|---|---|
| **Acknowledgement gate** | A target on a public host is refused unless you pass `--i-am-authorized` or set `scan.authorization.acknowledged: true`. Local, private-network and single-label hostnames (for example Docker service names) do not need it. The check also runs on `--dry-run`, so you find out before you scan. |
| **Audit trail** | Every report records who acknowledged what, how (flag or config), the note and contact you supplied, the scope class and the time. |
| **Gentle by default** | Public targets default to 2 requests per second. Concurrency, retries and total attempts are all bounded (the API additionally caps them per run). llmscan does not try to exhaust a target. |
| **`--dry-run`** | Prints the plan (probes, mutators, attempts, scope, rate limit) and sends nothing. |
| **Dashboard** | Shows the scope class and requires the acknowledgement before it will start a scan of a public host. The server enforces the same rule; the UI is a convenience. |
| **Hosted deployments** | The API can restrict targets to an allowlist of host patterns and block private and loopback addresses (SSRF hardening). See [SECURITY.md](SECURITY.md). |
| **Sensitive results** | `--redact` masks secrets and PII in stored transcripts. `llmscan report --redact` does the same for an existing report. |

These guards reduce accidents. They cannot stop a determined person from ignoring them, so the
responsibility for authorisation is yours.

## What the probes do, and what they never do

The built-in probes test whether an application's behaviour can be **hijacked**, not whether a model
will produce dangerous content.

- **Benign goals only.** A probe succeeds when the model prints a harmless marker (`LLMSCAN-` plus a random
  nonce), reveals a *planted* canary, repeats seeded test data, emits an inert payload, or calls a tool
  it should not. No probe asks a model for instructions for weapons, malware, self-harm or other
  genuinely harmful material.
- **Inert payloads.** Any URL a probe asks a model to write points at a reserved documentation domain
  (`.example`, `.test`, `.invalid`), `localhost`, or the cloud metadata address, which a probe makes a
  model *write* and which nothing ever fetches.
- **No tool execution.** The scanner records the tool calls a target *attempts*. It never runs them.
- **Automatically enforced.** `tests/test_probe_safety.py` fails the build if a probe mentions a
  forbidden topic, links to an untrusted reference, or points a payload at a real host.

### Side effects on the target: read this before scanning an agent or a RAG app

llmscan does not execute tools, but **your application might**. Two probe families can change state in
the system under test:

- **Excessive-agency probes** ask an agent to delete files, send email, run SQL or call internal APIs.
  Against an agent wired to real tools and real data, a *successful* attack performs the real action.
- **Indirect-injection probes** can plant a poisoned document in a knowledge base (when you configure
  an `ingest` endpoint) and remove it afterwards; if a run is interrupted, cleanup may not happen.

So: **scan a sandboxed or staging deployment with fake tools, fake data and a disposable knowledge
base. Never point the agent and RAG probes at production.** A scan you cannot safely repeat is a scan
you should not run.

## Handling what you find

- **Reports are sensitive.** A successful leak probe means the transcript contains the leaked secret or
  PII. Treat reports like the data they quote: restrict access, do not attach them to public tickets,
  and delete them when they are no longer needed (`Store.purge(older_than_days)` for a database).
- **Use canaries, not real secrets.** Plant fake credentials and fake customer records in the system under
  test and list them in the target config (`canaries`, `known_sensitive`). Detection is then exact and
  no real data is ever at risk.
- **A resisted attack is not proof of safety.** ASR is a lower bound. Reports say so, and so should you.

## If you find a vulnerability

**In a system you were authorised to test:** report it to the owner privately, give them time to fix
it (90 days is a common norm), and do not publish exploit details for an unpatched system. Respect any
disclosure terms of the programme that authorised the test.

**In a system you were not authorised to test:** stop, do not probe further, and do not keep or share
any data you saw. If you believe the issue is serious, report it through the owner's security contact
or a coordinator such as your national CERT.

**In llmscan itself:** see [SECURITY.md](SECURITY.md) for how to report it.

## Contributing probes

A new probe must:

1. have a benign objective that a harmless marker, a planted canary or a tool-call check can prove;
2. carry OWASP LLM Top 10 and MITRE ATLAS tags, a description and remediation text;
3. use only reserved or inert hosts in payload URLs, and only trusted domains in `references`;
4. pass `llmscan probes validate` and `pytest tests/test_probe_safety.py`.

The format is defined by [`probes/probe.schema.json`](../probes/probe.schema.json) (print it with
`llmscan probes schema`); the generated [probe catalogue](PROBE_CATALOG.md) lists every existing probe.
