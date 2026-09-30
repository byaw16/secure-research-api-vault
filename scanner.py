"""A conservative scanner for likely secrets in a user-selected source folder."""

from __future__ import annotations

import re
from pathlib import Path

PATTERNS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private-key header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Assigned secret": re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}
SKIP_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
MAX_FILE_SIZE = 2 * 1024 * 1024


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}…{value[-4:]}"


def scan_folder(folder: Path) -> list[dict]:
    """Return metadata-only findings. Full secret values are never returned."""
    findings: list[dict] = []
    root = folder.resolve()
    for path in root.rglob("*"):
        if not path.is_file() or SKIP_PARTS.intersection(path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "file": str(path.relative_to(root)),
                        "line": line,
                        "type": kind,
                        "preview": _redact(match.group(0)),
                    }
                )
    return findings

