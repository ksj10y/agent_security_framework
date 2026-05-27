"""npm package reputation — OSV.dev + npm registry downloads + deps.dev.

Multi-source signal for an npm package:

1. **OSV.dev** — published vulnerabilities.
2. **api.npmjs.org/downloads/point/last-week** — popularity proxy
   (typosquats and brand-new malicious packages have near-zero downloads).
3. **deps.dev** — version history (age + count).

The download count is the highest-signal npm-specific feature — a brand
new package with 0 weekly downloads but a name confusingly close to a
popular library is the canonical typosquat pattern.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from . import _osv


DEPS_DEV_URL_FMT = "https://api.deps.dev/v3/systems/NPM/packages/{name}"
NPM_DOWNLOADS_URL_FMT = "https://api.npmjs.org/downloads/point/last-week/{name}"


def _http_get_json(url: str, *, timeout: int) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None


def _depsdev_signals(name: str, *, timeout: int) -> dict:
    # deps.dev expects URL-encoded scoped names (e.g. @types/node → %40types%2Fnode).
    encoded = urllib.parse.quote(name, safe="")
    payload = _http_get_json(
        DEPS_DEV_URL_FMT.format(name=encoded), timeout=timeout,
    )
    if not payload:
        return {"depsdev_status": "unavailable"}
    versions = payload.get("versions") or []
    if not versions:
        return {"depsdev_status": "no_versions"}
    pubs = [v.get("publishedAt") for v in versions if v.get("publishedAt")]
    pubs.sort()
    return {
        "depsdev_status": "success",
        "version_count": len(versions),
        "earliest_published": pubs[0] if pubs else None,
        "latest_published": pubs[-1] if pubs else None,
    }


def _npm_downloads_signal(name: str, *, timeout: int) -> dict:
    encoded = urllib.parse.quote(name, safe="")
    payload = _http_get_json(
        NPM_DOWNLOADS_URL_FMT.format(name=encoded), timeout=timeout,
    )
    if not payload:
        return {"npm_downloads_status": "unavailable"}
    downloads = payload.get("downloads")
    if downloads is None:
        return {"npm_downloads_status": "no_data"}
    return {
        "npm_downloads_status": "success",
        "downloads_last_week": int(downloads),
        "downloads_window_start": payload.get("start"),
        "downloads_window_end": payload.get("end"),
    }


def _popularity_bucket(downloads: int | None) -> str:
    if downloads is None:
        return "unknown"
    if downloads == 0:
        return "zero"
    if downloads < 100:
        return "very_low"
    if downloads < 10_000:
        return "low"
    if downloads < 1_000_000:
        return "moderate"
    return "high"


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    name = node.get("name") or ""
    if not name:
        return None

    osv_payload = _osv.query(name, "npm", timeout=timeout)
    if osv_payload is None:
        osv_signal = {"vuln_count": 0, "severities": [], "ids": []}
        osv_status = "unavailable"
    else:
        osv_signal = _osv.signal_from_payload(name, "npm", osv_payload)
        osv_status = "success"

    downloads = _npm_downloads_signal(name, timeout=timeout)
    depsdev = _depsdev_signals(name, timeout=timeout)

    from ._typosquat import check as _typosquat_check
    typosquat = _typosquat_check(name, "npm")

    from ._known_bad import is_known_bad_npm
    from ._ossf_malicious import is_ossf_malicious
    known_bad_datadog = is_known_bad_npm(name)
    known_bad_ossf = is_ossf_malicious(name, "npm")
    known_bad = known_bad_datadog or known_bad_ossf
    known_bad_sources = [
        s for s, hit in [("DataDog", known_bad_datadog), ("OSSF", known_bad_ossf)] if hit
    ]

    dl = downloads.get("downloads_last_week")
    signal = {
        "source": "npm-multi",
        "target_type": "package",
        "target_name": name,
        "ecosystem": "npm",
        "status": "success",
        "osv_status": osv_status,
        "vuln_count": osv_signal.get("vuln_count", 0),
        "severities": osv_signal.get("severities", []),
        "ids": osv_signal.get("ids", []),
        "downloads_last_week": dl,
        "popularity_bucket": _popularity_bucket(dl),
        "version_count": depsdev.get("version_count"),
        "earliest_published": depsdev.get("earliest_published"),
        "typosquat": {
            "status": typosquat["status"],
            "closest": typosquat["closest"],
            "distance": typosquat["distance"],
        },
        "known_bad_package": known_bad,
        "known_bad_sources": known_bad_sources,
    }
    crit = signal["severities"].count("CRITICAL")
    high = signal["severities"].count("HIGH")
    summary_parts = [
        f"OSV {signal['vuln_count']} vulns ({crit} CRIT, {high} HIGH)",
        f"npm last-week downloads={dl} bucket={signal['popularity_bucket']}",
    ]
    if depsdev.get("version_count") is not None:
        summary_parts.append(
            f"deps.dev {depsdev['version_count']} versions, first {depsdev.get('earliest_published','?')[:10]}"
        )
    if typosquat["status"] == "near":
        summary_parts.append(
            f"⚠ TYPOSQUAT-SUSPECT: {typosquat['distance']} edits from {typosquat['closest']!r}"
        )
    if known_bad:
        summary_parts.insert(0, f"⚠ KNOWN-BAD-PACKAGE ({'+'.join(known_bad_sources)})")
    signal["summary"] = f"npm:{name} — " + "; ".join(summary_parts)
    return signal
