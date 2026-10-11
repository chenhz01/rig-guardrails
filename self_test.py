#!/usr/bin/env python3
"""self_test battery for rig-guardrails (functional / errors / edges).

Run:  python self_test.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import rig_guardrails as rg  # noqa: E402

HERE = Path(__file__).parent
PY = sys.executable or "python"

VALID = {
    "schema": "rig-guardrails/v1",
    "defaults": {"unknown_seat": "deny", "unknown_command": "ask"},
    "seats": {
        "pilot": {
            "role": "worker",
            "overrides": {"lifecycle": "ask"},
            "allowlist": [
                {"id": "deploy-staging", "pattern": "rig deploy staging*",
                 "decision": "allow", "expires": "2099-12-31"},
            ],
        },
        "observer": {"role": "readonly"},
    },
}


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, data, name="policy.json") -> Path:
        p = self.d / name
        p.write_text(json.dumps(data) if not isinstance(data, str) else data,
                     encoding="utf-8")
        return p


# ------------------------------------------------------------- functional

class Functional(TempCase):
    def test_validate_ok(self):
        rg.validate_policy(VALID)

    def test_class_defaults(self):
        self.assertEqual(rg.eval_command(VALID, "pilot", "git status")["decision"], "allow")
        self.assertEqual(rg.eval_command(VALID, "pilot", "npm install x")["decision"], "ask")
        self.assertEqual(rg.eval_command(VALID, "pilot", "rm -rf /")["decision"], "deny")

    def test_seat_override_applies(self):
        # observer has no override -> lifecycle default ask; pilot also ask.
        # give observer an explicit override in a variant policy:
        p = json.loads(json.dumps(VALID))
        p["seats"]["observer"]["overrides"] = {"lifecycle": "deny"}
        self.assertEqual(rg.eval_command(p, "observer", "rig up")["decision"], "deny")
        self.assertEqual(rg.eval_command(p, "observer", "rig up")["matched_by"], "seat-override")

    def test_allowlist_grants_exception(self):
        r = rg.eval_command(VALID, "pilot", "rig deploy staging web")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["matched_by"], "allowlist")

    def test_allowlist_narrower_than_override(self):
        r = rg.eval_command(VALID, "pilot", "rig deploy production web")
        self.assertEqual(r["decision"], "ask")  # override lifecycle=ask, no allowlist hit

    def test_revoke_removes_exception(self):
        p = json.loads(json.dumps(VALID))
        p = rg.revoke(p, "pilot", "deploy-staging")
        r = rg.eval_command(p, "pilot", "rig deploy staging web")
        self.assertEqual(r["decision"], "ask")

    def test_grant_then_eval_roundtrip(self):
        p = self.write(json.loads(json.dumps(VALID)))
        policy = rg.load_policy(p)
        policy = rg.grant(policy, "observer", "run-tests", "pytest -q*", "allow", None)
        rg.save_policy(policy, p)
        r = rg.eval_command(rg.load_policy(p), "observer", "pytest -q tests/")
        self.assertEqual(r["decision"], "allow")
        # revoke via CLI
        res = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "revoke",
                              str(p), "--seat", "observer", "--id", "run-tests"],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        r2 = rg.eval_command(rg.load_policy(p), "observer", "pytest -q tests/")
        # falls back to built-in class default: pytest* is ordinary -> allow
        self.assertEqual(r2["decision"], "allow")
        self.assertEqual(r2["matched_by"], "class-default")

    def test_cli_eval_deny_exit_1(self):
        p = self.write(VALID)
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "eval", str(p),
                            "--seat", "pilot", "--command", "rm -rf /"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("DENY", r.stdout)
        rj = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "eval", str(p),
                             "--seat", "pilot", "--command", "rm -rf /", "--json"],
                            capture_output=True, text=True)
        self.assertEqual(json.loads(rj.stdout)["matched_by"], "class-default")


# ------------------------------------------------------------ error paths

class ErrorPaths(TempCase):
    def test_wrong_schema(self):
        bad = dict(VALID, schema="rig-guardrails/v9")
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)

    def test_destructive_weakening_rejected(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["overrides"] = {"destructive": "allow"}
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)

    def test_destructive_allowlist_rejected(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["allowlist"].append(
            {"id": "evil", "pattern": "rm -rf tmp/*", "decision": "allow"})
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)

    def test_bad_decision_value(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["overrides"] = {"lifecycle": "maybe"}
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)

    def test_bad_expiry_format(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["allowlist"][0]["expires"] = "next tuesday"
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)

    def test_malformed_json_file(self):
        p = self.d / "bad.json"
        p.write_text("{nope", encoding="utf-8")
        with self.assertRaises(rg.PolicyError):
            rg.load_policy(p)

    def test_missing_file(self):
        with self.assertRaises(rg.PolicyError):
            rg.load_policy(self.d / "nope.json")

    def test_revoke_unknown_entry(self):
        with self.assertRaises(rg.PolicyError):
            rg.revoke(json.loads(json.dumps(VALID)), "pilot", "ghost")

    def test_grant_duplicate_id(self):
        p = json.loads(json.dumps(VALID))
        with self.assertRaises(rg.PolicyError):
            rg.grant(p, "pilot", "deploy-staging", "rig deploy canary*", "allow", None)

    def test_cli_validate_bad_exit_2(self):
        p = self.write(dict(VALID, schema="x"), "bad.json")
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "validate", str(p)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


# ----------------------------------------------------------- extreme edges

class ExtremeEdges(TempCase):
    def test_unknown_seat_uses_default(self):
        r = rg.eval_command(VALID, "ghost", "git status")
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["matched_by"], "default")

    def test_expired_allowlist_ignored(self):
        r = rg.eval_command(VALID, "pilot", "rig deploy staging web",
                            today="2099-12-31")  # expires == today -> expired (<=)
        self.assertEqual(r["decision"], "ask")

    def test_allowlist_future_expiry_ok(self):
        r = rg.eval_command(VALID, "pilot", "rig deploy staging web",
                            today="2026-01-01")
        self.assertEqual(r["decision"], "allow")

    def test_empty_seats_object(self):
        p = {"schema": "rig-guardrails/v1", "defaults": {}, "seats": {}}
        rg.validate_policy(p)
        self.assertEqual(rg.eval_command(p, "any", "ls")["decision"], "deny")

    def test_unknown_command_defaults_to_ask(self):
        r = rg.eval_command(VALID, "pilot", "frobnicate --zzz")
        self.assertIsNone(r["class"])
        self.assertEqual(r["decision"], "ask")

    def test_case_insensitive_matching(self):
        self.assertEqual(rg.classify_command("  GIT STATUS  "), "ordinary")
        self.assertEqual(rg.classify_command("RM -RF /"), "destructive")

    def test_huge_policy_eval_fast(self):
        p = {"schema": "rig-guardrails/v1", "defaults": {}, "seats": {
            f"s{i}": {"role": "worker"} for i in range(300)}}
        t0 = time.perf_counter()
        for i in range(0, 300, 30):
            rg.eval_command(p, f"s{i}", "git status")
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 2.0)

    def test_deny_trumps_allow_when_class_mismatch(self):
        # destructive command can never be allow-listed (validated), and
        # deny decision propagates with exit code 1 through the CLI.
        p = self.write(VALID)
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "eval", str(p),
                            "--seat", "ghost", "--command", "sudo rm -rf /"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


# ------------------------------------------------------- round-2 additions

class RoundTwo(TempCase):
    def test_classes_subcommand(self):
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "classes",
                            "git status", "rm -rf /", "frobnicate --x"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("-> ordinary", r.stdout)
        self.assertIn("-> destructive", r.stdout)
        self.assertIn("-> unknown", r.stdout)

    def test_allowlist_cannot_be_too_broad(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["allowlist"].append(
            {"id": "wide", "pattern": "git *", "decision": "allow"})
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)  # 'git *' globs into destructive 'git push --force*'

    def test_ask_override_on_destructive_rejected(self):
        bad = json.loads(json.dumps(VALID))
        bad["seats"]["pilot"]["overrides"] = {"destructive": "ask"}
        with self.assertRaises(rg.PolicyError):
            rg.validate_policy(bad)  # only deny allowed for destructive

    def test_allowlist_ask_decision_permitted(self):
        p = json.loads(json.dumps(VALID))
        p["seats"]["pilot"]["allowlist"].append(
            {"id": " cautious ", "pattern": "docker compose up *", "decision": "ask"})
        rg.validate_policy(p)  # narrowing to ask is fine

    def test_eval_matches_longest_prefix_semantics_first_entry_wins(self):
        p = json.loads(json.dumps(VALID))
        p["seats"]["pilot"]["allowlist"] = [
            {"id": "deny-deploy", "pattern": "rig deploy *", "decision": "deny"},
            {"id": "allow-staging", "pattern": "rig deploy staging*",
             "decision": "allow", "expires": "2099-12-31"},
        ]
        r = rg.eval_command(p, "pilot", "rig deploy staging web")
        self.assertEqual(r["matched_by"], "allowlist")
        self.assertEqual(r["decision"], "deny")  # first listed entry wins
        self.assertEqual(r["reason"], "allowlist entry 'deny-deploy' "
                                      "(expires: never)")

    def test_save_policy_is_deterministic_and_validated(self):
        p = self.d / "pol.json"
        policy = json.loads(json.dumps(VALID))
        rg.save_policy(policy, p)
        first = p.read_text(encoding="utf-8")
        rg.save_policy(json.loads(first), p)
        self.assertEqual(first, p.read_text(encoding="utf-8"))


# ------------------------------------------------------- v0.1.2 differentiation

class Differentiation(TempCase):
    def test_drift_flags_growth_only_seat(self):
        old = json.loads(json.dumps(VALID))
        new = json.loads(json.dumps(VALID))
        new["seats"]["pilot"]["allowlist"].append(
            {"id": "extra-1", "pattern": "rig deploy canary*", "decision": "allow"})
        new["seats"]["pilot"]["allowlist"].append(
            {"id": "extra-2", "pattern": "pytest tests/tmp/*", "decision": "ask"})
        d = rg.drift(old, new)
        pilot = [s for s in d["seats"] if s["seat"] == "pilot"][0]
        self.assertEqual(pilot["added"], ["extra-1", "extra-2"])
        self.assertEqual(pilot["removed"], [])
        self.assertTrue(d["creep"])
        self.assertIn("only grew", d["creep_note"])

    def test_drift_detects_expiry_extension(self):
        old = json.loads(json.dumps(VALID))
        new = json.loads(json.dumps(VALID))
        new["seats"]["pilot"]["allowlist"][0]["expires"] = "2099-12-31"
        old["seats"]["pilot"]["allowlist"][0]["expires"] = "2026-11-01"
        d = rg.drift(old, new)
        pilot = [s for s in d["seats"] if s["seat"] == "pilot"][0]
        self.assertEqual(pilot["extended"], ["deploy-staging"])
        self.assertEqual(pilot["added"], [])
        self.assertEqual(pilot["removed"], [])

    def test_drift_clean_when_revocation_happened(self):
        old = json.loads(json.dumps(VALID))
        new = rg.revoke(json.loads(json.dumps(VALID)), "pilot", "deploy-staging")
        d = rg.drift(old, new)
        pilot = [s for s in d["seats"] if s["seat"] == "pilot"][0]
        self.assertEqual(pilot["removed"], ["deploy-staging"])
        self.assertFalse(d["creep"])

    def test_drift_empty_policies(self):
        empty = {"schema": "rig-guardrails/v1", "defaults": {}, "seats": {}}
        d = rg.drift(empty, empty)
        self.assertEqual(d["seats"], [])
        self.assertEqual(d["totals"], {"added": 0, "removed": 0, "net": 0})
        self.assertFalse(d["creep"])

    def test_cluster_groups_identical_seats(self):
        p = json.loads(json.dumps(VALID))
        p["seats"]["copilot"] = {"role": "worker"}            # same table as observer
        clusters = rg.cluster_seats(p)
        self.assertEqual(len(clusters), 2)
        joined = [c for c in clusters if "observer" in c]
        self.assertEqual(len(joined), 1)
        self.assertIn("copilot", joined[0])
        self.assertNotIn("pilot", joined[0])  # pilot has an allowlist -> differs

    def test_cluster_separates_different_seats(self):
        p = json.loads(json.dumps(VALID))
        p["seats"]["lax"] = {"role": "worker",
                             "allowlist": [{"id": "inst", "pattern": "npm install *",
                                            "decision": "allow"}]}
        clusters = rg.cluster_seats(p)
        # pilot (staging allowlist), observer, lax (npm-install allow) all differ
        self.assertEqual(len(clusters), 3)
        self.assertEqual([c for c in clusters if "lax" in c][0], ["lax"])

    def test_cluster_deterministic(self):
        a = rg.cluster_seats(VALID)
        b = rg.cluster_seats(VALID)
        self.assertEqual(a, b)

    def test_simulate_counts_decisions(self):
        r = rg.simulate(VALID, "pilot",
                        ["git status", "rig up", "rm -rf build", "frobnicate --x"])
        self.assertEqual(r["summary"], {"allow": 1, "ask": 2, "deny": 1})
        by_cmd = {x["command"]: x for x in r["results"]}
        self.assertEqual(by_cmd["git status"]["decision"], "allow")
        self.assertEqual(by_cmd["rm -rf build"]["decision"], "deny")

    def test_simulate_leaves_policy_unchanged(self):
        before = json.dumps(VALID, sort_keys=True)
        rg.simulate(VALID, "pilot", ["git status", "rig up", "rm -rf build"])
        self.assertEqual(before, json.dumps(VALID, sort_keys=True))

    def test_cli_drift_exit_codes(self):
        old = self.write(json.loads(json.dumps(VALID)), "old.json")
        grown = json.loads(json.dumps(VALID))
        grown["seats"]["pilot"]["allowlist"].append(
            {"id": "x1", "pattern": "rig deploy canary*", "decision": "allow"})
        new = self.write(grown, "new.json")
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "drift",
                            str(old), str(new)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("CREEP", r.stdout)
        shrunk = self.write(rg.revoke(json.loads(json.dumps(VALID)),
                                      "pilot", "deploy-staging"), "new2.json")
        r2 = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "drift",
                             str(old), str(shrunk)], capture_output=True, text=True)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)

    def test_cli_simulate_exit_codes(self):
        p = self.write(VALID)
        r_deny = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "simulate", str(p),
                                 "--seat", "pilot", "--command", "rm -rf build"],
                                capture_output=True, text=True)
        self.assertEqual(r_deny.returncode, 1)
        self.assertIn("deny: 1", r_deny.stdout)
        r_ok = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "simulate", str(p),
                               "--seat", "pilot", "--command", "git status"],
                              capture_output=True, text=True)
        self.assertEqual(r_ok.returncode, 0)

    def test_cli_cluster_subcommand(self):
        p = self.write(VALID)
        r = subprocess.run([PY, str(HERE / "rig_guardrails.py"), "cluster", str(p)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("pilot", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
