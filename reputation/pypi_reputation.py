"""PyPI package reputation — OSV.dev + deps.dev + PyPI metadata.

Multi-source signal for a Python package:

1. **OSV.dev** — published vulnerabilities (CVSS / advisory severity).
2. **deps.dev** — version history (age = first published, count, recency).
3. **PyPI metadata** — author/maintainer + release count + license + project URLs.

The three sources are complementary: OSV tells you known CVEs, deps.dev
tells you how long the package has existed and how active it is, PyPI
tells you who claims to maintain it. The verifier uses all three.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from . import _osv


DEPS_DEV_URL_FMT = "https://api.deps.dev/v3/systems/PYPI/packages/{name}"
PYPI_METADATA_URL_FMT = "https://pypi.org/pypi/{name}/json"


def _http_get_json(url: str, *, timeout: int) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None


def _depsdev_signals(name: str, *, timeout: int) -> dict:
    # deps.dev expects URL-encoded names; PyPI package strings sometimes carry
    # spaces or dots (e.g. "Roblox.com") that break a bare ``.format`` substitute.
    encoded = urllib.parse.quote(name, safe="")
    payload = _http_get_json(DEPS_DEV_URL_FMT.format(name=encoded), timeout=timeout)
    if not payload:
        return {"depsdev_status": "unavailable"}
    versions = payload.get("versions") or []
    if not versions:
        return {"depsdev_status": "no_versions"}
    pubs = [v.get("publishedAt") for v in versions if v.get("publishedAt")]
    pubs.sort()
    deprecated_count = sum(1 for v in versions if v.get("isDeprecated"))
    return {
        "depsdev_status": "success",
        "version_count": len(versions),
        "earliest_published": pubs[0] if pubs else None,
        "latest_published": pubs[-1] if pubs else None,
        "deprecated_count": deprecated_count,
    }


def _pypi_metadata_signals(name: str, *, timeout: int) -> dict:
    payload = _http_get_json(PYPI_METADATA_URL_FMT.format(name=name), timeout=timeout)
    if not payload:
        return {"pypi_status": "unavailable"}
    info = payload.get("info") or {}
    releases = payload.get("releases") or {}
    return {
        "pypi_status": "success",
        "declared_author": info.get("author") or info.get("author_email") or "",
        "license": info.get("license") or "",
        "release_count": len(releases),
        "summary_text": (info.get("summary") or "")[:200],
        "home_page": info.get("home_page") or info.get("project_urls", {}).get("Homepage") if isinstance(info.get("project_urls"), dict) else "",
    }


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    name = node.get("name") or ""
    if not name:
        return None

    # 1) OSV vulnerabilities
    osv_payload = _osv.query(name, "PyPI", timeout=timeout)
    if osv_payload is None:
        osv_signal = {"osv_status": "unavailable", "vuln_count": 0, "severities": [], "ids": []}
    else:
        osv_signal = _osv.signal_from_payload(name, "PyPI", osv_payload)
        osv_signal["osv_status"] = "success"

    # 2) deps.dev maturity
    depsdev = _depsdev_signals(name, timeout=timeout)

    # 3) PyPI metadata
    pypi_meta = _pypi_metadata_signals(name, timeout=timeout)

    # 4) Typosquat — local Levenshtein vs popular PyPI top-100
    from ._typosquat import check as _typosquat_check
    typosquat = _typosquat_check(name, "PyPI")

    # 5) Known-bad package — two independent primary sources.
    from ._known_bad import is_known_bad_pypi
    from ._ossf_malicious import is_ossf_malicious
    known_bad_datadog = is_known_bad_pypi(name)
    known_bad_ossf = is_ossf_malicious(name, "pypi")
    known_bad = known_bad_datadog or known_bad_ossf
    known_bad_sources = [
        s for s, hit in [("DataDog", known_bad_datadog), ("OSSF", known_bad_ossf)] if hit
    ]

    signal = {
        "source": "pypi-multi",
        "target_type": "package",
        "target_name": name,
        "ecosystem": "PyPI",
        "status": "success",
        "vuln_count": osv_signal.get("vuln_count", 0),
        "severities": osv_signal.get("severities", []),
        "ids": osv_signal.get("ids", []),
        "version_count": depsdev.get("version_count"),
        "earliest_published": depsdev.get("earliest_published"),
        "latest_published": depsdev.get("latest_published"),
        "declared_author": pypi_meta.get("declared_author", ""),
        "license": pypi_meta.get("license", ""),
        "release_count": pypi_meta.get("release_count"),
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
    parts = []
    parts.append(f"OSV {signal['vuln_count']} vulns ({crit} CRIT, {high} HIGH)")
    if depsdev.get("version_count") is not None:
        parts.append(f"deps.dev {depsdev['version_count']} versions, first {depsdev.get('earliest_published','?')[:10]}")
    if pypi_meta.get("release_count") is not None:
        parts.append(f"PyPI {pypi_meta['release_count']} releases, author={pypi_meta['declared_author'][:40]!r}")
    if typosquat["status"] == "near":
        parts.append(f"⚠ TYPOSQUAT-SUSPECT: {typosquat['distance']} edits from {typosquat['closest']!r}")
    if known_bad:
        parts.insert(0, f"⚠ KNOWN-BAD-PACKAGE ({'+'.join(known_bad_sources)})")
    signal["summary"] = f"PyPI:{name} — " + "; ".join(parts)
    return signal
