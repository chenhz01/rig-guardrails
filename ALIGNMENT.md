# Alignment Audit (Rules 85-100 / 16 items) — rig-guardrails

Audited: 2026-10-11, post round-2 iteration (v0.1.1) by W1; round-3 re-audit (differentiation vs anchor) v0.1.2 by D2. Evidence is reproducible.

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section | N/A | Non-security-research repo (QA/permissions tooling); no dangerous content in code or docs. |
| 2 | Privacy de-identification | PASS | grep scan `(sk-\|ghp_\|api_key\|password=)`: 0 real hits (1 false positive "ask-decision"); contact = hcac4735@agent.qq.com only; no real names. |
| 3 | Copyright boundary | PASS | 100% original code/text; v0.1.2 "differs" section restates the anchor's features in original wording (no >50-word copied text; anchor README re-checked); MIT LICENSE present. |
| 4 | Fact-check annotations | PASS | Perf figures: self_test-measured with repro command in README FAQ (44 tests, ~2.5 s); anchor capability list cross-checked against its README on 2026-10-11 and dated; scaling claims marked [estimated]. |
| 5 | Confidence grading | PASS | README has 2 explicit Confidence labels (High/Medium) with one-line rationale each. |
| 6 | Minimal Fallback (PLAN B) | PASS | README "Minimal Fallback (PLAN B)" section: no-install degraded usage. |
| 7 | Quickstart time budget | PASS | Quickstart states per-step costs (~0.2-0.5 s each); v0.1.2 step 5 included. |
| 8 | Rule-conflict arbitration | PASS | README "Design Trade-offs" states priority order explicitly. |
| 9 | Version changelog | PASS | CHANGELOG.md: v0.1.0 + v0.1.1 + v0.1.2, round-3 improvements itemized per capability. |
| 10 | Exemption instruction (session rule) | N/A | Session-level governance; not applicable to static repo content. |
| 11 | External-knowledge cutoff | PASS | Time-sensitive statements (vocabulary, classes, tool names, anchor-feature checks) tagged "as of 2026-10-11". |
| 12 | Explicit assumptions | PASS | README [Core Assumptions] lists 4 premises. |
| 13 | Logic-check triad | PASS | self_test 44/44 OK (`python self_test.py` ~2.5 s): functional 8 + error paths 10 + extreme edges 8 + round-2 6 + v0.1.2 differentiation 12. |
| 14 | Socratic FAQ | PASS | FAQ contains "When NOT to use this tool?" with concrete counter-scenarios. |
| 15 | Pareto iteration | PASS | v0.1.1->v0.1.2: 3 new capabilities absent from the anchor README, each with stated factual basis; tests 32->44 (+37.5%); recorded in CHANGELOG. |
| 16 | Ultimate minimal entry | PASS | First paragraph ≤60 words, states what/who-needs-it with a judgment sentence. |

Additional: Limits & Second-order Effects section present per rule 16 (二阶思维).

Anchor-differentiation note (D2): the direct anchor (dbuxton/agentgate) was deep-read via its README on 2026-10-11. Its documented capability list and the three gaps this repo now fills are recorded in README "How this differs from agentgate". Honest asymmetry (the anchor's broader runtime surface) is stated there too — the differentiation claim is two-directional, not one-sided.
