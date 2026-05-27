"""GitHub repo reputation — Scorecard + repo metadata + Advisory DB.

Three complementary signals, all no-auth public APIs (rate-limited only):

1. **OpenSSF Scorecard** (``api.securityscorecards.dev``) — 0–10 quality
   score with per-check breakdown (Maintained, Dangerous-Workflow, etc.).
2. **GitHub repo metadata** (``api.github.com/repos/{o}/{r}``) — stars,
   forks, last push, archived flag, default branch, license. Scorecard
   already covers some maintained-ness, but the raw signals (e.g. "pushed
   3 days ago") add interpretable context for the verifier.
3. **GitHub Advisory DB** (``api.github.com/advisories``) — affects
   query returns CVE/GHSA records that reference the repo's name. Some
   advisories live in GHSA before OSV mirrors them.

Bucket policy: ``RED`` if Scorecard < 3.0 OR repo is archived OR last push
> 365 days OR any HIGH/CRITICAL GHSA advisory; ``GREEN`` if Scorecard ≥ 5.0
AND active in last 90 days AND no high-severity advisories; ``YELLOW``
otherwise.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

SCORECARD_URL_FMT = "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
GITHUB_REPO_URL_FMT = "https://api.github.com/repos/{owner}/{repo}"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


_GITHUB_SOURCE_RE = re.compile(
    r"(?:https?://github\.com/|git@github\.com:|github\.com/)([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


def _parse_owner_repo(source: str) -> tuple[str, str] | None:
    m = _GITHUB_SOURCE_RE.search(source.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _get_json(url: str, *, timeout: int, params: dict | None = None) -> dict | list | None:
    if params:
        from urllib.parse import urlencode
        url = f"{url}?{urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "chanever-reputation-bot/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None


def _query_scorecard(owner: str, repo: str, *, timeout: int) -> dict | None:
    payload = _get_json(SCORECARD_URL_FMT.format(owner=owner, repo=repo), timeout=timeout)
    return payload if isinstance(payload, dict) else None


def _query_github_metadata(owner: str, repo: str, *, timeout: int) -> dict | None:
    payload = _get_json(GITHUB_REPO_URL_FMT.format(owner=owner, repo=repo), timeout=timeout)
    return payload if isinstance(payload, dict) else None


def _query_github_advisories(owner: str, repo: str, *, timeout: int) -> list[dict]:
    """Look up GHSA advisories that reference this repo by name."""
    payload = _get_json(
        GITHUB_ADVISORIES_URL,
        timeout=timeout,
        params={"affects": f"{owner}/{repo}", "per_page": "20"},
    )
    return payload if isinstance(payload, list) else []


def _days_since(iso_ts: str | None) -> int | None:
    if not iso_ts:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def _bucket(scorecard_score: float, gh_meta: dict | None, advisories: list[dict],
            *, known_bad_org: bool = False) -> str:
    """Combine signals into RED / YELLOW / GREEN bucket.

    Hard precedence:
      known_bad_org (from cited audit) → RED (overrides every positive signal)
      else RED if any of: Scorecard < 3.0 / repo archived / last push >365 days /
        HIGH+ severity advisory referenced.
      GREEN if all healthy. Otherwise YELLOW.
    """
    if known_bad_org:
        return "RED"
    has_high_advisory = any(
        (a.get("severity") or "").lower() in {"high", "critical"}
        for a in advisories
    )
    last_push_days = _days_since((gh_meta or {}).get("pushed_at"))
    archived = bool((gh_meta or {}).get("archived"))
    if scorecard_score < 3.0 or archived or has_high_advisory or (
        last_push_days is not None and last_push_days > 365
    ):
        return "RED"
    if (
        scorecard_score >= 5.0
        and not has_high_advisory
        and last_push_days is not None
        and last_push_days <= 90
    ):
        return "GREEN"
    return "YELLOW"


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    source = node.get("source") or ""
    parsed = _parse_owner_repo(source)
    if not parsed:
        return {
            "source": "github-multi",
            "target_type": "github_repo",
            "target_name": source,
            "status": "skipped",
            "summary": "Only github.com URLs are supported.",
        }
    owner, repo = parsed
    name = f"{owner}/{repo}"

    from ._known_bad import is_known_bad_github_org
    known_bad_org = is_known_bad_github_org(owner)

    scorecard = _query_scorecard(owner, repo, timeout=timeout)
    gh_meta = _query_github_metadata(owner, repo, timeout=timeout)
    advisories = _query_github_advisories(owner, repo, timeout=timeout)

    if scorecard is None and gh_meta is None and not advisories:
        if known_bad_org:
            # Local audit-derived signal still actionable even without API
            # data. RED bucket + cited source surfaced. The citation lives
            # in ``_known_bad.KNOWN_BAD_GITHUB_ORGS`` per-entry comment.
            return {
                "source": "github-multi",
                "target_type": "github_repo",
                "target_name": name,
                "status": "success",
                "score_bucket": "RED",
                "known_bad_org": True,
                "known_bad_source": "see reputation/_known_bad.py KNOWN_BAD_GITHUB_ORGS",
                "summary": f"{name} [RED] — ⚠ KNOWN-BAD-ORG (cited audit); external APIs unreachable",
            }
        return {
            "source": "github-multi",
            "target_type": "github_repo",
            "target_name": name,
            "status": "unavailable",
            "summary": f"All reputation sources unreachable for {name}",
        }

    score = float((scorecard or {}).get("score") or 0.0) if scorecard else 0.0
    checks = (scorecard or {}).get("checks") or []
    low_scoring = [
        {"name": c.get("name"), "score": c.get("score")}
        for c in checks
        if isinstance(c.get("score"), (int, float)) and c["score"] <= 2
    ]

    bucket = _bucket(score, gh_meta, advisories, known_bad_org=known_bad_org)
    last_push_days = _days_since((gh_meta or {}).get("pushed_at"))
    high_advisories = [
        a for a in advisories
        if (a.get("severity") or "").lower() in {"high", "critical"}
    ]

    parts = []
    if scorecard:
        parts.append(f"Scorecard {score:.1f} ({len(low_scoring)} checks ≤ 2)")
    if gh_meta:
        stars = gh_meta.get("stargazers_count")
        archived = gh_meta.get("archived")
        parts.append(
            f"GH: {stars}★, pushed {last_push_days}d ago"
            + (", ARCHIVED" if archived else "")
        )
    if advisories:
        parts.append(f"{len(advisories)} GHSA advisories ({len(high_advisories)} HIGH+)")
    if known_bad_org:
        parts.insert(0, "⚠ KNOWN-BAD-ORG (cited audit)")
    summary = f"{name} [{bucket}] — " + "; ".join(parts) if parts else f"{name} [{bucket}]"

    return {
        "source": "github-multi",
        "target_type": "github_repo",
        "target_name": name,
        "status": "success",
        "score_bucket": bucket,
        "known_bad_org": known_bad_org,
        "known_bad_source": (
            "see reputation/_known_bad.py KNOWN_BAD_GITHUB_ORGS"
            if known_bad_org else None
        ),
        "scorecard": {
            "score": score,
            "low_scoring_checks": low_scoring[:10],
            "commit": (scorecard or {}).get("repo", {}).get("commit") if scorecard else None,
            "date": (scorecard or {}).get("date") if scorecard else None,
        } if scorecard else None,
        "github_metadata": {
            "stars": (gh_meta or {}).get("stargazers_count"),
            "forks": (gh_meta or {}).get("forks_count"),
            "open_issues": (gh_meta or {}).get("open_issues_count"),
            "pushed_at": (gh_meta or {}).get("pushed_at"),
            "last_push_days_ago": last_push_days,
            "archived": (gh_meta or {}).get("archived"),
            "default_branch": (gh_meta or {}).get("default_branch"),
            "license": ((gh_meta or {}).get("license") or {}).get("spdx_id") if gh_meta else None,
        } if gh_meta else None,
        "advisories": {
            "total": len(advisories),
            "high_severity": len(high_advisories),
            "ids": [a.get("ghsa_id") for a in advisories[:10] if a.get("ghsa_id")],
        } if advisories else None,
        "summary": summary,
    }
