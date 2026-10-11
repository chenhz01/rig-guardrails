# Changelog — rig-guardrails

## v0.1.2 — 2026-10-11 (round-3 iteration: differentiation vs agentgate)

Deep-read of the direct anchor (dbuxton/agentgate) showed its README documents runtime enforcement (tokens, profiles, team RBAC, quotas, audit log, MCP) but no policy-snapshot drift analysis, no static seat analytics, and no batch rehearsal. Three read-only analytics capabilities added over the same decision engine; none appears in the anchor's README (checked 2026-10-11). Tests 32 -> 44 (+37.5%).

### Added
- **`drift(old_policy, new_policy)`** — permission-creep audit between two policy snapshots: per-seat allowlist adds/removes, expiry-extension detection (same id whose `expires` moved later), and a `creep` flag when entries only grew and were never revoked between audits. New `drift` CLI subcommand, exit 1 on creep.
- **`cluster_seats(policy)`** — probes every seat with a fixed command battery and groups seats with identical effective decision tables (mergeable duplicates, default-only singletons). New `cluster` CLI subcommand.
- **`simulate(policy, seat, commands)`** — batch dry-run: per-command decisions plus allow/ask/deny summary, mutates nothing. New `simulate` CLI subcommand (repeatable `--command` or `--script` file), exit 1 if any deny.
- 12 new tests covering drift flags/extension detection/revocation-clean/empty, cluster grouping/separation/determinism, simulate counts/immutability, and CLI exit codes for all three subcommands.

### Changed
- CLI dispatch order: `drift` is handled before loading a single policy file (it takes two snapshots).
- README: new "How this differs from agentgate" section (factual comparison, both directions — the anchor's broader runtime surface is credited, not minimized); Quickstart step 5 added.

## v0.1.1 — 2026-10-11 (round-2 iteration: safety invariant hardening)