#!/usr/bin/env python3
"""rig-guardrails: seat-level least-privilege policy for agent teams.

A language-agnostic permission spec library extracted from the guardrail
pattern of multi-agent rigs: each *seat* (a persistent agent role) gets an
explicit policy over command classes, plus a revocable allowlist for narrow
exceptions. Nothing here executes commands — it only decides
allow / ask / deny and explains why.

Policy schema (rig-guardrails/v1):
{
  "schema": "rig-guardrails/v1",
  "defaults": {"unknown_seat": "deny", "unknown_command": "ask"},
  "seats": {
    "pilot": {
      "role": "worker",
      "overrides": {"lifecycle": "ask"},          # class -> decision
      "allowlist": [
        {"id": "deploy-staging", "pattern": "rig deploy staging*",
         "decision": "allow", "expires": "2026-12-31"}
      ]
    }
  }
}

Decision order: allowlist match (unexpired) > seat override > class default.
Class defaults: ordinary=allow, lifecycle=ask, destructive=deny.
A seat override may never weaken `destructive` below deny (validated).

CLI: validate | eval | classes | grant | revoke. Pure standard library.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

SCHEMA = "rig-guardrails/v1"
DECISIONS = ("allow", "ask", "deny")
CLASSES = ("ordinary", "lifecycle", "destructive")

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Built-in command classification (fnmatch globs, matched case-insensitively).
BUILTIN_CLASSES = {
    "ordinary": (
        "git status*", "git diff*", "git log*", "git show*",
        "npm test*", "npm run *", "pytest*", "python *", "node *",
        "ls*", "cat*", "head*", "tail*", "rg*", "grep*", "wc*",
    ),
    "lifecycle": (
        "rig up*", "rig down*", "rig restart*", "rig deploy*",
        "npm install*", "npm ci*", "pip install*",
        "docker compose up*", "docker compose down*", "docker build*",
    ),
    "destructive": (
        "rm *", "rmdir *", "git push --force*", "git push -f*",
        "git reset --hard*", "git clean*", "git checkout -- *",
        "drop table *", "drop database *", "truncate table *",
        "chmod 777*", "sudo *", "sh *", "bash *", "curl *| *", "*| rm *",
    ),
}

CLASS_DEFAULTS = {"ordinary": "allow", "lifecycle": "ask", "destructive": "deny"}


class PolicyError(Exception):
    """Policy is invalid (validation or I/O)."""


# ------------------------------------------------------------- validation

def classify_command(command: str) -> str | None:
    c = command.strip().lower()
    for cls, patterns in BUILTIN_CLASSES.items():
        for pat in patterns:
            if fnmatch.fnmatch(c, pat):
                return cls
    return None


def validate_policy(policy, source: str = "<policy>") -> None:
    if not isinstance(policy, dict):
        raise PolicyError(f"{source}: policy must be a JSON object")
    if policy.get("schema") != SCHEMA:
        raise PolicyError(f"{source}: schema must be {SCHEMA!r}, got {policy.get('schema')!r}")
    defaults = policy.get("defaults", {})
    if not isinstance(defaults, dict):
        raise PolicyError(f"{source}: 'defaults' must be an object")
    for k in ("unknown_seat", "unknown_command"):
        v = defaults.get(k)
        if v is not None and v not in DECISIONS:
            raise PolicyError(f"{source}: defaults.{k} must be one of {DECISIONS}")
    seats = policy.get("seats", {})
    if not isinstance(seats, dict):
        raise PolicyError(f"{source}: 'seats' must be an object")
    for name, seat in seats.items():
        where = f"{source}: seats[{name!r}]"
        if not isinstance(seat, dict):
            raise PolicyError(f"{where} must be an object")
        if not isinstance(seat.get("role", "worker"), str):
            raise PolicyError(f"{where}: 'role' must be a string")
        overrides = seat.get("overrides", {})
        if not isinstance(overrides, dict):
            raise PolicyError(f"{where}: 'overrides' must be an object")
        for cls, dec in overrides.items():
            if cls not in CLASSES:
                raise PolicyError(f"{where}: unknown command class {cls!r}")
            if dec not in DECISIONS:
                raise PolicyError(f"{where}: overrides.{cls} must be one of {DECISIONS}")
            if cls == "destructive" and dec != "deny":
                # hard safety rule: seat-level policy cannot weaken destructive
                raise PolicyError(
                    f"{where}: overrides.destructive={dec!r} weakens the "
                    f"'destructive=deny' baseline; use a narrow allowlist entry instead")
        allowlist = seat.get("allowlist", [])
        if not isinstance(allowlist, list):
            raise PolicyError(f"{where}: 'allowlist' must be a list")
        ids = set()
        for i, entry in enumerate(allowlist):
            ew = f"{where}.allowlist[{i}]"
            if not isinstance(entry, dict):
                raise PolicyError(f"{ew} must be an object")
            eid = entry.get("id")
            if not isinstance(eid, str) or not eid.strip():
                raise PolicyError(f"{ew}: missing non-empty 'id'")
            if eid in ids:
                raise PolicyError(f"{ew}: duplicate allowlist id {eid!r}")
            ids.add(eid)
            pat = entry.get("pattern")
            if not isinstance(pat, str) or len(pat.strip()) < 4 or pat.strip() == "*":
                raise PolicyError(f"{ew}: 'pattern' must be a specific glob (>=4 chars, not '*')")
            if entry.get("decision") not in DECISIONS:
                raise PolicyError(f"{ew}: 'decision' must be one of {DECISIONS}")
            exp = entry.get("expires")
            if exp is not None and not (isinstance(exp, str) and DATE_RE.match(exp)):
                raise PolicyError(f"{ew}: 'expires' must be YYYY-MM-DD or null")
            if entry.get("decision") == "allow":
                probe = pat.replace("*", "x")
                if classify_command(probe) == "destructive":
                    raise PolicyError(f"{ew}: allowlist cannot allow-list a destructive pattern")
                # breadth guard: a trailing-wildcard whose literal prefix reaches
                # into the destructive family (e.g. 'git *' covers force-push)
                base = pat.rstrip("*").strip().lower()
                for dp in BUILTIN_CLASSES["destructive"]:
                    dbase = dp.rstrip("*").strip()
                    if dbase.startswith(base) or base.startswith(dbase):
                        raise PolicyError(
                            f"{ew}: allowlist pattern {pat!r} is broad enough to "
                            f"cover destructive command(s) like {dp!r}")


# ----------------------------------------------------------------- engine

def _expired(entry, today: str) -> bool:
    exp = entry.get("expires")
    return bool(exp and str(exp) <= today)


def eval_command(policy: dict, seat: str, command: str, today: str = "2026-10-11") -> dict:
    """Resolve a decision. Never raises for unknown seats/commands."""
    cls = classify_command(command)
    seats = policy.get("seats", {})
    seat_policy = seats.get(seat)

    base = {
        "seat": seat, "command": command, "class": cls,
        "decision": None, "matched_by": None, "reason": "",
    }
    if seat_policy is None:
        default_unknown_seat = policy.get("defaults", {}).get("unknown_seat", "deny")
        base.update(decision=default_unknown_seat, matched_by="default",
                    reason=f"seat {seat!r} has no policy; defaults.unknown_seat applies")
        return base

    # 1. allowlist (unexpired, first match wins)
    for entry in seat_policy.get("allowlist", []):
        if _expired(entry, today):
            continue
        if fnmatch.fnmatch(command.strip().lower(), entry["pattern"].lower()):
            base.update(decision=entry["decision"], matched_by="allowlist",
                        reason=f"allowlist entry {entry['id']!r} "
                               f"(expires: {entry.get('expires') or 'never'})")
            return base

    # 2. seat override
    ov = seat_policy.get("overrides", {})
    if cls is not None and cls in ov:
        base.update(decision=ov[cls], matched_by="seat-override",
                    reason=f"seat override for class {cls!r}")
        return base

    # 3. class default / unknown command default
    if cls is None:
        dec = policy.get("defaults", {}).get("unknown_command", "ask")
        base.update(decision=dec, matched_by="default",
                    reason="command matches no known class; defaults.unknown_command applies")
        return base
    base.update(decision=CLASS_DEFAULTS[cls], matched_by="class-default",
                reason=f"built-in default for class {cls!r}")
    return base


# ---------------------------------------------------------------- storage

def load_policy(path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"policy file not found: {p}")
    try:
        policy = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc
    validate_policy(policy, source=str(p))
    return policy


def save_policy(policy: dict, path) -> None:
    validate_policy(policy, source=str(path))
    Path(path).write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def grant(policy: dict, seat: str, entry_id: str, pattern: str, decision: str,
          expires: str | None) -> dict:
    seats = policy.setdefault("seats", {}).setdefault(seat, {"role": "worker"})
    allowlist = seats.setdefault("allowlist", [])
    if any(e.get("id") == entry_id for e in allowlist):
        raise PolicyError(f"allowlist id {entry_id!r} already exists for seat {seat!r}")
    allowlist.append({"id": entry_id, "pattern": pattern,
                      "decision": decision, "expires": expires})
    validate_policy(policy)  # re-check safety rules on the merged policy
    return policy


def revoke(policy: dict, seat: str, entry_id: str) -> dict:
    seats = policy.get("seats", {})
    if seat not in seats:
        raise PolicyError(f"unknown seat {seat!r}")
    allowlist = seats[seat].get("allowlist", [])
    remaining = [e for e in allowlist if e.get("id") != entry_id]
    if len(remaining) == len(allowlist):
        raise PolicyError(f"allowlist id {entry_id!r} not found for seat {seat!r}")
    seats[seat]["allowlist"] = remaining
    return policy


# ---------------------------------------------------------------- analytics
# v0.1.2: drift / clustering / dry-run — all read-only over the policy dict.

PROBE_COMMANDS = (
    "git status", "git diff", "npm test", "pytest -q", "ls",
    "rig up", "rig deploy staging", "npm install pkg",
    "docker compose up web", "rm -rf build", "sudo ls",
    "git push --force", "frobnicate --x",
)


def drift(old_policy: dict, new_policy: dict) -> dict:
    """Permission-creep audit between two policy snapshots.

    Per seat: which allowlist ids were added / removed, and which entries
    had their `expires` pushed further out (a quieter form of creep: the
    grant did not grow, it just stopped dying). creep=True when, across the
    whole policy, entries were only ever added and never removed between
    the two audits.
    """
    old_seats = old_policy.get("seats", {})
    new_seats = new_policy.get("seats", {})
    rows = []
    tot_added = tot_removed = 0
    for seat in sorted(set(old_seats) | set(new_seats)):
        old_al = {e.get("id"): e for e in old_seats.get(seat, {}).get("allowlist", [])}
        new_al = {e.get("id"): e for e in new_seats.get(seat, {}).get("allowlist", [])}
        added = sorted(set(new_al) - set(old_al))
        removed = sorted(set(old_al) - set(new_al))
        extended = sorted(
            i for i in set(old_al) & set(new_al)
            if str(old_al[i].get("expires") or "") < str(new_al[i].get("expires") or ""))
        tot_added += len(added)
        tot_removed += len(removed)
        rows.append({"seat": seat, "added": added, "removed": removed,
                     "extended": extended,
                     "net": len(new_al) - len(old_al)})
    creep = tot_added > 0 and tot_removed == 0
    note = ("allowlist entries only grew between the two audits: no revocations "
            "recorded" if creep else "the allowlist did not only grow between "
            "the two audits")
    return {"seats": rows,
            "totals": {"added": tot_added, "removed": tot_removed,
                       "net": tot_added - tot_removed},
            "creep": creep, "creep_note": note}


def cluster_seats(policy: dict, probes=None) -> list:
    """Group seats whose effective decision tables are identical.

    Probes each seat with the same battery of commands (one or more per
    class + unknown) via eval_command and clusters seats with identical
    decision tuples. Useful hygiene signal: a cluster of N identical seats
    means N-1 policies that can be merged; a singleton with an empty
    allowlist is a seat that only ever hits class defaults.
    """
    probes = tuple(probes) if probes else PROBE_COMMANDS
    sig = {}
    for seat in policy.get("seats", {}):
        table = tuple(eval_command(policy, seat, c)["decision"] for c in probes)
        sig.setdefault(table, []).append(seat)
    return sorted(sorted(members) for members in sig.values())


def simulate(policy: dict, seat: str, commands, today: str = "2026-10-11") -> dict:
    """Dry-run a batch of commands for one seat without touching anything.

    Same decision engine as eval_command, applied to a list; the policy is
    never mutated and no state is written. Returns per-command decisions
    plus allow/ask/deny counts so a policy can be rehearsed before deploy.
    """
    results = []
    summary = {"allow": 0, "ask": 0, "deny": 0}
    for cmd in commands:
        r = eval_command(policy, seat, cmd, today=today)
        results.append({"command": cmd, "decision": r["decision"],
                        "matched_by": r["matched_by"]})
        summary[r["decision"]] += 1
    return {"seat": seat, "results": results, "summary": summary}


# -------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="rig-guardrails",
        description="Seat-level least-privilege policy spec for agent teams: "
                    "validate, evaluate, grant, revoke. Spec-only, executes nothing.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_v = sub.add_parser("validate", help="validate a policy file")
    ap_v.add_argument("file")

    ap_c = sub.add_parser("classes", help="show which class a command falls into")
    ap_c.add_argument("commands", nargs="+", help="one or more commands to classify")

    ap_e = sub.add_parser("eval", help="evaluate a command for a seat")
    ap_e.add_argument("file")
    ap_e.add_argument("--seat", required=True)
    ap_e.add_argument("--command", required=True)
    ap_e.add_argument("--today", default="2026-10-11", help="ISO date for expiry checks")
    ap_e.add_argument("--json", action="store_true")

    ap_g = sub.add_parser("grant", help="add an allowlist entry (writes file)")
    ap_g.add_argument("file")
    ap_g.add_argument("--seat", required=True)
    ap_g.add_argument("--id", required=True)
    ap_g.add_argument("--pattern", required=True)
    ap_g.add_argument("--decision", choices=DECISIONS, default="allow")
    ap_g.add_argument("--expires", default=None)

    ap_r = sub.add_parser("revoke", help="remove an allowlist entry (writes file)")
    ap_r.add_argument("file")
    ap_r.add_argument("--seat", required=True)
    ap_r.add_argument("--id", required=True)

    ap_d = sub.add_parser("drift", help="creep audit between two policy "
                                        "snapshots (exit 1 on creep)")
    ap_d.add_argument("old")
    ap_d.add_argument("new")

    ap_cl = sub.add_parser("cluster", help="group seats with identical "
                                           "effective decision tables")
    ap_cl.add_argument("file")

    ap_s = sub.add_parser("simulate", help="dry-run a batch of commands for "
                                           "a seat (no state changes)")
    ap_s.add_argument("file")
    ap_s.add_argument("--seat", required=True)
    ap_s.add_argument("--command", dest="commands", action="append", default=[],
                      help="command to simulate; repeatable")
    ap_s.add_argument("--script", default=None,
                      help="file with one command per line")
    ap_s.add_argument("--today", default="2026-10-11", help="ISO date for expiry checks")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "validate":
            load_policy(args.file)
            print(f"policy valid: {args.file}")
            return 0
        if args.cmd == "classes":
            for cmd in args.commands:
                cls = classify_command(cmd)
                print(f"{cmd!r} -> {cls or 'unknown'}")
            return 0
        if args.cmd == "drift":
            old_p = load_policy(args.old)
            new_p = load_policy(args.new)
            d = drift(old_p, new_p)
            print(f"DRIFT AUDIT {args.old} -> {args.new}")
            for row in d["seats"]:
                extra = f"  extended: {row['extended']}" if row["extended"] else ""
                print(f"  {row['seat']}: +{len(row['added'])} -{len(row['removed'])} "
                      f"(net {row['net']:+d})  "
                      f"added={row['added']} removed={row['removed']}{extra}")
            print(f"totals: {d['totals']}  verdict: "
                  f"{'CREEP' if d['creep'] else 'no creep'} ({d['creep_note']})")
            return 1 if d["creep"] else 0
        policy = load_policy(args.file)
        if args.cmd == "eval":
            result = eval_command(policy, args.seat, args.command, today=args.today)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{result['decision'].upper():5} seat={result['seat']} "
                      f"class={result['class']} via={result['matched_by']} "
                      f"({result['reason']})")
            return {"allow": 0, "ask": 0, "deny": 1}[result["decision"]]
        if args.cmd == "grant":
            policy = grant(policy, args.seat, args.id, args.pattern,
                           args.decision, args.expires)
            save_policy(policy, args.file)
            print(f"granted {args.decision} for {args.pattern!r} -> seat {args.seat!r} "
                  f"(id={args.id})")
            return 0
        if args.cmd == "revoke":
            policy = revoke(policy, args.seat, args.id)
            save_policy(policy, args.file)
            print(f"revoked {args.id!r} from seat {args.seat!r}")
            return 0
        if args.cmd == "cluster":
            clusters = cluster_seats(policy)
            print(f"seat clusters by effective decision table ({len(clusters)}):")
            for c in clusters:
                print(f"  [{' | '.join(c)}]")
            return 0
        if args.cmd == "simulate":
            cmds = list(args.commands)
            if args.script:
                cmds.extend(
                    ln.strip() for ln in Path(args.script).read_text(
                        encoding="utf-8").splitlines() if ln.strip())
            if not cmds:
                print("error: nothing to simulate (use --command or --script)",
                      file=sys.stderr)
                return 2
            r = simulate(policy, args.seat, cmds, today=args.today)
            for row in r["results"]:
                print(f"{row['decision'].upper():5} {row['command']} "
                      f"(via {row['matched_by']})")
            s = r["summary"]
            print(f"summary: allow: {s['allow']}  ask: {s['ask']}  deny: {s['deny']} "
                  f"(dry-run; nothing was executed or changed)")
            return 1 if s["deny"] else 0
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
