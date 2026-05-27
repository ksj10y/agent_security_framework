"""Agent-skill **reputation** — source/identity trust only.

This module answers ONE question for the verifier:
  "Is the external source of this skill trustworthy?"

It does NOT analyze the skill's contents — that is the static analyzer's
job (`static_analyzers/skill_analyzer.py` runs phrase scans, cross-file walks,
and semgrep against execution surfaces). Keeping the modules separated makes
each function's reliability claim narrow and testable: this module verifies
*provenance / identity*, the static analyzer verifies *what the skill says
to do*.

Signals reported here:

1. **distribution_source** — local path / URL pattern → channel classification
   (anthropic-official / omc-marketplace / claude-code-plugin-cache /
   claude-code-builtin / github-other / huggingface / local-development /
   unknown). Path / URL strings are harder to forge than the SKILL.md
   frontmatter text, so this is the strongest *positive* trust signal.
2. **declared_author** + **TRUSTED_AUTHORS** allowlist — does the frontmatter
   claim a publisher we recognise? Easy to spoof, so it counts only as a
   *secondary* signal alongside signature / distribution.
3. **KNOWN_BAD_AUTHORS** — explicit *negative* reputation: publishers
   identified as malicious in public audits (e.g. the "hightower6eu" group
   flagged by SkillSieve / Koi Security on ClawHub, Jan–Feb 2026).
4. **signature_present** — file ``.sig`` / ``.asc`` / ``.sigstore`` next to
   the manifest. We do NOT verify the signature today; presence alone is a
   weak positive, absence is a real negative.
5. **manifest_completeness** — does the SKILL.md frontmatter include
   license + description + author? Empty frontmatter has lower trust
   regardless of what content says (this is metadata sanity, not content
   analysis).

The trust bucket combines these signals with hard precedence — a hit in
``KNOWN_BAD_AUTHORS`` overrides any positive signal; otherwise the
distribution-channel verdict short-circuits the author/signature check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Publishers identified as malicious in public audits (cited list in _known_bad).
from ._known_bad import KNOWN_BAD_SKILL_AUTHORS as KNOWN_BAD_AUTHORS


_FRONTMATTER_RE = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)


# ─────────────────────────── identity allowlists ──────────────────────────────


# Publishers whose declared_author string is treated as a *positive* signal.
# Curated — anyone with filesystem access can write `author: anthropic` so
# this list is only a secondary signal alongside signature / distribution.
TRUSTED_AUTHORS = {
    "anthropic", "anthropic, pbc", "anthropic-pbc",
    "claude", "claude-code", "claude.ai",
    "modelcontextprotocol", "model context protocol",
    "openai", "deepmind", "google-deepmind", "google",
    "github", "microsoft",
    "datadog",  # GuardDog publisher
}


# ─────────────────────────── distribution-source classifier ───────────────────


def _classify_distribution_source(source: str) -> dict[str, str]:
    """Classify where the skill was received from.

    Returns one of:
        anthropic-official        — anthropics/* repo URL or plugin cache path
        claude-code-plugin-cache  — installed via /plugin install (non-OMC)
        omc-marketplace           — oh-my-claudecode plugin marketplace
        claude-code-builtin       — bundled with Claude Code
        github-other              — github.com URL not anthropics
        huggingface               — huggingface.co URL
        local-development         — local path with no known plugin cache prefix
        unknown                   — could not classify

    Path / URL string matching is harder to forge than frontmatter text, so
    this is the strongest positive trust signal in the module. Note we DO
    NOT verify that the path content matches what the plugin manifest
    expected — that would require sigstore-style signature checks.
    """
    s = (source or "").lower()
    if not s:
        return {"trust": "unknown", "evidence": "no source provided"}

    if "github.com/anthropics/" in s or "anthropics/claude-skills" in s:
        return {"trust": "anthropic-official", "evidence": "anthropics/* repo URL"}
    if "anthropic.com/" in s or "claude.ai/" in s:
        return {"trust": "anthropic-official", "evidence": "anthropic domain URL"}
    if "github.com/" in s:
        return {"trust": "github-other", "evidence": "non-anthropics github URL"}
    if "huggingface.co/" in s:
        return {"trust": "huggingface", "evidence": "huggingface.co URL"}

    # Local-path heuristics — plugin cache layout introduced by Claude Code:
    #   ~/.claude/plugins/cache/<vendor>/<pkg>/<ver>/skills/<skill>/
    if "/.claude/plugins/cache/omc/" in s or "oh-my-claudecode" in s:
        return {"trust": "omc-marketplace", "evidence": "OMC plugin cache path"}
    if "/.claude/plugins/cache/anthropics/" in s:
        return {"trust": "anthropic-official", "evidence": "Anthropic plugin cache path"}
    if "/.claude/plugins/cache/" in s:
        return {"trust": "claude-code-plugin-cache", "evidence": "Claude Code plugin cache path"}
    if "/.claude/skills/" in s:
        return {"trust": "claude-code-builtin", "evidence": "Claude Code builtin skill path"}

    if s.startswith("/home/") or s.startswith("/workspace/") or s.startswith("/tmp/") or s.startswith("/var/"):
        return {"trust": "local-development", "evidence": "local path with no known plugin cache prefix"}

    return {"trust": "unknown", "evidence": f"could not classify path/URL {s[:60]!r}"}


# ─────────────────────────── identity helpers ─────────────────────────────────


def _read_frontmatter(text: str) -> dict[str, str]:
    m = _FRONTMATTER_RE.search(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    for line in m.group("body").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _author_in_set(declared: str, allowlist: set[str]) -> bool:
    if not declared:
        return False
    norm = declared.lower().strip().strip(".,").strip()
    if norm in allowlist:
        return True
    for entry in allowlist:
        if re.search(rf"\b{re.escape(entry)}\b", norm):
            return True
    return False


# ─────────────────────────── bucket combinator ────────────────────────────────


def _bucket(
    *, signed: bool, author_trusted: bool, author_known_bad: bool,
    distribution_trust: str,
) -> str:
    """Combine source signals into a single label. Hard precedence:

        author in KNOWN_BAD_AUTHORS    →  known-bad-author      (RED)
        distribution = anthropic-…     →  official-distribution / signed-trusted
        distribution = plugin cache    →  plugin-installed-trusted
        signed + trusted-author        →  signed-trusted
        trusted-author                 →  unsigned-trusted
        signed                         →  signed-unknown-author
        distribution = github/HF       →  remote-unknown-author
        distribution = local-dev       →  local-development-untrusted
        else                           →  unsigned-unknown-author

    Distribution provenance short-circuits the author-string check because
    a signed plugin manifest is harder to forge than the SKILL.md
    frontmatter text.
    """
    if author_known_bad:
        return "known-bad-author"
    if distribution_trust == "anthropic-official":
        return "signed-trusted" if signed else "official-distribution"
    if distribution_trust in {"claude-code-builtin", "omc-marketplace", "claude-code-plugin-cache"}:
        return "plugin-installed-trusted"
    if signed and author_trusted:
        return "signed-trusted"
    if author_trusted:
        return "unsigned-trusted"
    if signed:
        return "signed-unknown-author"
    if distribution_trust in {"github-other", "huggingface"}:
        return "remote-unknown-author"
    if distribution_trust == "local-development":
        return "local-development-untrusted"
    return "unsigned-unknown-author"


# ─────────────────────────── public API ───────────────────────────────────────


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    """Source/identity reputation for a skill node.

    ``timeout`` is accepted for API parity with other reputation modules —
    this module performs no network calls.
    """
    del timeout

    scan_root_str = node.get("scan_root")
    if not scan_root_str:
        return {
            "source": "skill-heuristic",
            "target_type": "skill",
            "target_name": node.get("name", ""),
            "status": "skipped",
            "summary": "Remote skill — local provenance signals unavailable.",
        }

    scan_root = Path(scan_root_str)
    declared_author = ""
    declared_purpose = ""
    declared_license = ""
    signature_present = False
    manifest_files: list[str] = []

    for surface in node.get("instruction_surfaces") or []:
        p = scan_root / surface
        if not p.is_file():
            continue
        manifest_files.append(surface)
        text = p.read_text(encoding="utf-8", errors="replace")
        if surface.lower().endswith("skill.md"):
            fm = _read_frontmatter(text)
            declared_author = declared_author or fm.get("author", "") or fm.get("publisher", "")
            declared_purpose = declared_purpose or fm.get("description", "") or fm.get("purpose", "")
            declared_license = declared_license or fm.get("license", "")
        elif surface.lower().endswith("manifest.json"):
            try:
                data = json.loads(text)
                declared_author = declared_author or str(data.get("author") or data.get("publisher") or "")
                declared_purpose = declared_purpose or str(data.get("description") or data.get("purpose") or "")
                declared_license = declared_license or str(data.get("license") or "")
            except (json.JSONDecodeError, OSError):
                pass

    for ext in (".sig", ".asc", ".sigstore"):
        if any((scan_root / f).exists() for f in (f"SKILL.md{ext}", f"manifest.json{ext}", f"skill.md{ext}")):
            signature_present = True
            break

    author_trusted = _author_in_set(declared_author, TRUSTED_AUTHORS)
    author_known_bad = _author_in_set(declared_author, KNOWN_BAD_AUTHORS)
    distribution = _classify_distribution_source(node.get("source") or scan_root_str)

    bucket = _bucket(
        signed=signature_present,
        author_trusted=author_trusted,
        author_known_bad=author_known_bad,
        distribution_trust=distribution["trust"],
    )

    manifest_incomplete = not (declared_purpose and declared_license and declared_author)

    summary_parts = [
        f"author={declared_author!r}",
        f"trusted_author={author_trusted}",
        f"known_bad_author={author_known_bad}",
        f"signed={signature_present}",
        f"dist={distribution['trust']}",
    ]
    if manifest_incomplete:
        summary_parts.append("manifest=incomplete")

    return {
        "source": "skill-reputation",
        "target_type": "skill",
        "target_name": node.get("name", ""),
        "status": "success",
        "declared_author": declared_author,
        "declared_purpose": declared_purpose[:200],
        "declared_license": declared_license,
        "signature_present": signature_present,
        "manifest_files": manifest_files[:10],
        "manifest_incomplete": manifest_incomplete,
        "distribution_source": distribution,
        "author_trusted": author_trusted,
        "author_known_bad": author_known_bad,
        "trust_bucket": bucket,
        "summary": f"Skill {bucket}: " + ", ".join(summary_parts),
    }
