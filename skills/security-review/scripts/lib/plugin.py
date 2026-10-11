"""The security-review plugin's fixed names, and its own manifest."""

from __future__ import annotations

import re
from pathlib import Path

from . import strictjson
from .strictjson import is_map, is_str

NAME = "security-review"
ROOT = Path(__file__).resolve().parents[2]
RUN_DIR_NAME = ".security-review-run"
TARGET_FILES_NAME = "target-files.json"
VOTES_PROVENANCE = "agy:security-review"
MODES = ("scan", "changes", "commit")
REPORT_DIR_PREFIX = "SECURITY-REVIEW-"
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}\Z")


def version() -> str | None:
    """The non-blank version string in the plugin's manifest, or None when there is not one."""
    try:
        manifest = strictjson.load(ROOT / "plugin.json")
    except (OSError, ValueError):
        return "1.0.0"
    if not is_map(manifest):
        return "1.0.0"
    declared = manifest.get("version")
    if not is_str(declared):
        return "1.0.0"
    return declared.strip() or "1.0.0"
