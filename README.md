# rig-guardrails

A language-agnostic permission spec library for agent teams: seat-level
least-privilege policies plus a revocable allowlist, expressed as plain JSON
and evaluated by a zero-dependency engine. It decides **allow / ask / deny**
for any command any seat wants to run — and explains which rule decided.
Spec-only: it executes nothing, ever.

**Confidence: High (>=85%)** for the decision engine and safety invariants
(deterministic, fully tested); **Medium (60-79%)** that the built-in command
classification covers a real team's command surface without edits.

## Problem

Multi-agent rigs converge on the same unstated guardrail: a seat runs
ordinary commands without prompting, lifecycle commands still ask, and
destructive ones are refused — with narrow, revocable exceptions. But that
policy lives inside each harness as code. The overlooked angle is that the
*policy itself* is portable: the same YAML/JSON could govern a Python CLI
agent, a Node harness, or a shell wrapper. Without a shared spec, every
team re-invents seat permissions — usually as "everything allowed, hope
the model behaves".

## How it works

- **Command classes** (built-in, case-insensitive globs): `ordinary`
  (git status, pytest, ...), `lifecycle` (rig up, npm install, docker
  compose up, ...), `destructive` (rm, sudo, force-push, drop table, ...).
  Unknown commands default to `ask`.
- **Decision order**: unexpired allowlist entry (first match) > seat
  override > class default (`ordinary=allow, lifecycle=ask,
  destructive=deny`).
- **Safety invariant** (validated, not advisory): seat overrides can never
  weaken `destructive` below deny, and allowlist entries can never
  allow-list a destructive pattern — including breadth-guarded globs like
  `git *` whose prefix reaches into the destructive family. Narrow
  exceptions must be explicit, expiring, and revocable by id.
- CLI: `validate` / `eval` (exit 0 allow/ask, 1 deny, 2 error) /
  `classes` (debug: which class does a command fall into?) / `grant` /
  `revoke` — grant and revoke round-trip the policy file so the harness or
  a human can operate the whitelist over time.

## Quickstart (~3 min)

```bash
# 1. Write a policy (see README example / self_test fixtures), then:
python rig_guardrails.py validate policy.json          # ~0.2 s

# 2. Evaluate commands for a seat (~0.2 s each)
python rig_guardrails.py eval policy.json --seat pilot --command "git status"        # ALLOW
python rig_guardrails.py eval policy.json --seat pilot --command "rig up"            # ASK
python rig_guardrails.py eval policy.json --seat pilot --command "rm -rf build"      # DENY

# 3. Debugging: why does this command classify that way? (~0.2 s)
python rig_guardrails.py classes "git status" "rm -rf /" "frobnicate --x"

# 4. Lifecycle of an exception: grant -> eval -> revoke (~0.5 s)
python rig_guardrails.py grant policy.json --seat pilot --id tmp-tests \
    --pattern "pytest tests/tmp/*" --decision allow --expires 2026-11-01
python rig_guardrails.py revoke policy.json --seat pilot --id tmp-tests

# 5. v0.1.2 lenses: creep audit / seat clusters / batch dry-run (~0.5 s each)
python rig_guardrails.py drift policy-old.json policy-new.json    # exit 1 = CREEP
python rig_guardrails.py cluster policy.json                      # identical decision tables
python rig_guardrails.py simulate policy.json --seat pilot \
    --command "git status" --command "rm -rf build"               # dry-run, no state
```

## How this differs from agentgate

The closest direct anchor is [dbuxton/agentgate](https://github.com/dbuxton/agentgate): identity-aware access control for AI agent tool permissions. Per its README it already does: per-user permission profiles (allow/deny globs), HMAC-SHA256 signed session tokens with instant revocation, per-tool-call enforcement (signature/expiry/revocation/user-active checks), team RBAC with union permission resolution, hourly rate limits and daily token quotas, an audit log of every enforcement decision, a FastAPI server with dashboard, an MCP server (permission pre-check, introspection, quota status, elevation requests), and Django/OpenAI/Anthropic integrations. It is a full runtime enforcement system; credit where due — this repo is the portable policy-data layer and does not attempt to replace it.

What this repo adds that the anchor's README does not document (checked 2026-10-11):

1. **Permission-creep audit between policy snapshots** — `drift old.json new.json` reports per-seat allowlist adds/removes, catches expiry extensions (a grant that did not grow but stopped dying), and exits 1 with a CREEP verdict when entries only ever grew between two audits. agentgate's README covers granting, enforcing, and revoking, but documents no policy-snapshot comparison or growth alarm.
2. **Seat clustering** — `cluster` probes every seat with a fixed command battery and groups seats with identical effective decision tables, surfacing mergeable duplicate policies and default-only singletons. The anchor resolves effective permissions per user at runtime, but documents no static policy-hygiene analysis.
3. **Batch dry-run simulation** — `simulate` rehearses a whole command list against a seat (per-command decisions + allow/ask/deny summary, exit 1 if any deny) without executing anything or mutating state. The anchor's `check_permission` is a single-call pre-check; no batch rehearsal appears in its README.

Honest asymmetry: the anchor has large capabilities this spec library deliberately lacks — signed tokens, a database, rate limiting, quotas, audit storage, a server, MCP, and framework adapters. The overlap is the mechanism family (deciding which agent may run which tool), not the artifact: agentgate is enforcement infrastructure, rig-guardrails is a diffable, version-controllable policy spec plus offline analytics over it.

## Why not X

| Alternative | Why not here |
|---|---|
| Harness-built-in permissions (per-tool prompts) | Locked to one harness's CLI; policy not portable, not diffable, not testable as data. |
| OS sandboxing (containers, seccomp) | Necessary defense-in-depth but binary (run/not-run); cannot express "ask a human first" or expire a grant next sprint. Use both — they compose. |
| YAML RBAC/IAM systems (K8s-style) | Built for services and users, not session-shaped agents; no command-class vocabulary, no ask semantics, heavy dependency for a local agent loop. |
| "Trust the model" + audit logs | Audit logs tell you what burned down; this refuses the match. Prevention > forensics. |

## Minimal Fallback (PLAN B)

No Python? The invariant worth keeping fits in a shell wrapper:

```bash
#!/bin/sh
# deny-first gate: only known-safe prefixes run without a human
case "$1" in
  git\ status|git\ diff|pytest*|npm\ test*) exec "$@" ;;
  *) echo "ASK: '$1' requires human approval"; exit 1 ;;
esac
```

You lose classes, expiry, seat policies, and explainability — but you keep
"destructive needs a human" in eight lines.

## Design Trade-offs

Priority: **deny destructive by default > explainability > coverage**.

- Globs over full shell parsing: predictable and language-agnostic; pays
  for it with blind spots (obfuscated commands classify as unknown ->
  default `ask`, which is the safe direction).
- Expiry compared as ISO date strings, timezone-free: simple and auditable;
  fine for day-granularity grants, wrong for minute-level TTLs (deliberate).
- Policy as a single JSON file with last-write-wins: no merge service; git
  review is the concurrency control.

## Limits & Second-order Effects

- **Rubber-stamp drift**: if `ask` becomes annoying, teams auto-approve —
  the ask tier decays into allow. Monitor ask-decline rates; a declining
  rate of ~0 means the classes need re-tuning.
- Policy files rot: as the command surface grows, unreviewed policies
  accumulate allowlist fossils. Revocation is a first-class CLI verb for
  this reason — use it.
- Deterministic classification is gameable by the supervised agent (encode
  payloads in allowed commands). This spec constrains *accident*, not
  *intent*; pair with OS sandboxing for adversarial settings.

## FAQ

**Q: When NOT to use this tool?**
A: When you need actual enforcement against a hostile process — this is a
decision function, not a sandbox; a process that ignores it is unconstrained.
Also skip it for single-user single-agent setups where you are the ask-tier.

**Q: Does it run the commands?**
A: Never. It returns decisions; your harness executes (or not).

**Q: Can I add my own command classes?**
A: Classes are built-in in v1; express custom grouping as allowlist entries
or seat overrides. A plugin scheme is deliberately deferred until two real
implementations need it.

**Q: How fast?**
A: Self-test measured: 44 tests including a 300-seat policy and full
grant/revoke CLI round-trips in ~2.5 s (`python self_test.py` reproduces);
per-eval cost is microseconds [estimated].

## [Core Assumptions]

1. Agent seats outlive single sessions, so permissions attach to the seat
   (role), not the conversation.
2. A three-tier decision space (allow/ask/deny) is sufficient; richer
   RBAC adds cost without changing agent-team behavior.
3. The built-in command classification matches typical dev workflows as of
   2026-10-11; teams with exotic toolchains will override via allowlist.
4. Policies are version-controlled artifacts reviewed by humans; the tool
   provides no multi-writer concurrency control.

---
Contact: hcac4735@agent.qq.com · License: MIT · Command classes as of 2026-10-11.
