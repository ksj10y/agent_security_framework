#!/usr/bin/env python3
"""Framework-level reliability benchmark.

Drives the *full* safeguard pipeline (classification → external target
extraction → asset_kind classifier → static_analyzers → reputation → shadow
sandbox → evidence builder → Claude CLI verifier → decision) over the same
labelled corpora the static/reputation module benches use, and reports a
per-family confusion matrix on the safeguard's final ``decision``.

Reads cases from ``/home/user/agent-mds/eval/benchmarks/{family}`` and feeds
each one through ``ShadowSandboxSafeguard.inspect(action, context)``. Per-case
the script also records the evidence package's stage statuses so it is
visible *why* the framework decided as it did (asset_kind / static /
reputation / sandbox).

Outcome semantics (per case, vs label):
  * malicious / mixed-malicious → ``decision != "allow"`` → **TP** (the
    framework correctly stopped real execution); ``decision == "allow"`` → **FN**
  * benign / mixed-benign       → ``decision == "allow"`` → **TN**;
    anything else → **FP**
  * exception while running the pipeline → **ERR** (kept separate so infra
    failures do not pollute accuracy)

Time budget: roughly 60-80s per case (Claude CLI asset_kind + sandbox +
docker semgrep + reputation + Claude CLI verifier). Start with a small
``--cap`` and scale up — full 192 census is multi-hour.

Run with everything on (mirrors README ``전체 동작 흐름``)::

    SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \\
    SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \\
    VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \\
    CLAUDE_CLI_MAX_TURNS=12 \\
    python bench/framework_reliability.py --cap 3
"""
from __future__ import annotations

import argparse
import inspect as _i
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.config import SecurityFrameworkConfig                       # noqa: E402
from security_framework.safeguard.shadow_sandbox_safeguard import ShadowSandboxSafeguard  # noqa: E402

BENCH = Path("/home/user/agent-mds/eval/benchmarks")


# ───────────────────────── per-family case resolvers ─────────────────────────


def _datadog_scan_root(case_dir: Path) -> Path:
    """Datadog cases keep the unpacked package under ``artifact/<...>/<pkg>/``.
    Descend to the first dir that contains ``setup.py`` or ``package.json``.
    """
    artifact = case_dir / "artifact"
    if artifact.is_dir():
        for sub in artifact.rglob("setup.py"):
            return sub.parent
        for sub in artifact.rglob("package.json"):
            return sub.parent
        return artifact
    return case_dir


def _label_by_prefix(name: str) -> str:
    """toolhijacker cases label themselves by name prefix (benign-*/malicious-*)."""
    return "malicious" if name.startswith("malicious") else "benign"


def _panel(family: str, label, limit: int | None, cmd: str, scan_resolver=None) -> list[dict]:
    root = BENCH / family
    if not root.is_dir():
        return []
    cases = sorted([p for p in root.iterdir() if p.is_dir()])
    if limit:
        cases = cases[:limit]
    out = []
    for case_dir in cases:
        scan_root = scan_resolver(case_dir) if scan_resolver else case_dir
        case_label = label(case_dir.name) if callable(label) else label
        out.append({
            "family": family,
            "label": case_label,
            "case": case_dir.name,
            "cwd": str(scan_root),
            "command": cmd,
        })
    return out


# ───────────────────────── outcome + evidence parsing ────────────────────────


def _classify_outcome(label: str, decision: str | None) -> str:
    if label == "benign":
        return "TN" if decision == "allow" else "FP"
    # malicious — anything that is not 'allow' counts as TP
    return "TP" if decision != "allow" else "FN"


def _read_stages(ep_path: str | None) -> dict:
    if not ep_path or not Path(ep_path).is_file():
        return {}
    try:
        ep = json.loads(Path(ep_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    eia = ep.get("external_interaction_analysis") or {}
    return {
        "external_env":       (ep.get("current_action") or {}).get("external_env"),
        "asset_kind":         (eia.get("asset_kind") or {}).get("status"),
        "asset_kind_kind":    (eia.get("asset_kind") or {}).get("kind"),
        "static_status":      (eia.get("static_analysis") or {}).get("status"),
        "static_findings":    len((eia.get("static_analysis") or {}).get("findings", [])),
        "reputation_status":  (eia.get("reputation_analysis") or {}).get("status"),
        "reputation_signals": len((eia.get("reputation_analysis") or {}).get("signals", [])),
        "sandbox_status":     (ep.get("shadow_agent_execution") or {}).get("execution_status"),
    }


# ────────────────────────────────── main ─────────────────────────────────────


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=3,
                        help="cases per family (0 = full census, multi-hour)")
    parser.add_argument("--out", default="/tmp/framework_reliability.json")
    parser.add_argument("--families", default="",
                        help="comma-separated subset, e.g. 'datadog-pypi,benign-pypi'")
    args = parser.parse_args(argv)
    cap = args.cap or None

    cfg = SecurityFrameworkConfig.from_env()
    if "config" in _i.signature(ShadowSandboxSafeguard.__init__).parameters:
        sg = ShadowSandboxSafeguard(cfg)
    else:
        sg = ShadowSandboxSafeguard()

    print(f"flags: static={cfg.static_analysis_enabled} "
          f"reputation={cfg.reputation_analysis_enabled} "
          f"sandbox={getattr(cfg, 'shadow_sandbox_enabled', '?')} "
          f"verifier={getattr(cfg, 'verifier_mode', '?')}  "
          f"sandbox_img={getattr(cfg, 'sandbox_docker_image', '?')}")

    # full panel — same structure as bench/static_analysis_reliability.py so
    # the framework bench is directly comparable to the static-only bench.
    panels = (
        _panel("datadog-pypi",    "malicious", cap, "pip install pkg",  _datadog_scan_root)
        + _panel("datadog-npm",   "malicious", cap, "npm install pkg",  _datadog_scan_root)
        + _panel("malicious-repos", "malicious", cap, "pip install .")
        + _panel("skill-inject",  "malicious", cap, "cat SKILL.md")
        + _panel("toolhijacker",  _label_by_prefix, cap, "cat SKILL.md")
        + _panel("benign-pypi",   "benign", cap, "pip install pkg")
        + _panel("benign-skills", "benign", cap, "cat SKILL.md")
        + _panel("benign-tools",  "benign", cap, "cat SKILL.md")
    )
    if args.families:
        keep = {f.strip() for f in args.families.split(",") if f.strip()}
        panels = [p for p in panels if p["family"] in keep]

    print(f"panel size: {len(panels)}\n")

    confusion_per_family: dict[str, Counter] = {}
    confusion_total: Counter = Counter()
    rows: list[dict] = []
    t_total = time.monotonic()
    for i, case in enumerate(panels, start=1):
        family = case["family"]
        action = {"type": "command", "command": case["command"],
                  "reason": "framework reliability benchmark"}
        context = {"cwd": case["cwd"], "history": [], "step": i - 1}
        t0 = time.monotonic()
        try:
            res = sg.inspect(action, context)
            elapsed = time.monotonic() - t0
            decision = res.get("decision")
            outcome = _classify_outcome(case["label"], decision)
            stages = _read_stages(res.get("evidence_package_path"))
            row = {**case, "decision": decision, "outcome": outcome,
                   "elapsed_s": round(elapsed, 1),
                   "reason": str(res.get("reason", ""))[:160], **stages}
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            outcome = "ERR"
            row = {**case, "decision": None, "outcome": "ERR",
                   "elapsed_s": round(elapsed, 1),
                   "error": f"{type(exc).__name__}: {exc}"[:200]}

        rows.append(row)
        confusion_per_family.setdefault(family, Counter())[outcome] += 1
        confusion_total[outcome] += 1
        mark = {"TP": "✓", "TN": "✓"}.get(outcome, "✗")
        print(f"  {mark} [{outcome:3s}] {family:16s}/{case['case'][:30]:30s} "
              f"→ {row.get('decision') or 'ERR':5s}  "
              f"ak={row.get('asset_kind')} static={row.get('static_status')}"
              f"(f={row.get('static_findings', 0)}) rep={row.get('reputation_status')}"
              f"({row.get('reputation_signals', 0)}) sb={row.get('sandbox_status')} "
              f"[{elapsed:.0f}s]")

    elapsed_total = time.monotonic() - t_total

    print("\n=== Per-family confusion ===")
    for fam in sorted(confusion_per_family):
        print(f"  {fam:18s} {dict(confusion_per_family[fam])}")
    print(f"\n=== TOTAL ===\n  {dict(confusion_total)}  (n={sum(confusion_total.values())}, "
          f"elapsed={elapsed_total / 60:.1f} min)")

    out = Path(args.out)
    out.write_text(json.dumps({
        "confusion_total": dict(confusion_total),
        "confusion_per_family": {k: dict(v) for k, v in confusion_per_family.items()},
        "elapsed_min": round(elapsed_total / 60, 2),
        "rows": rows,
    }, indent=2, default=str))
    print(f"Details → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
