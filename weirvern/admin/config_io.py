"""Safe, comment-preserving read/write of the Weirvern `.env` file.

Design constraints (why this is not just `dict` + `write_text`):
  * The `.env` is a human-edited file with comments and ordering that the
    operator cares about — rewriting it as a flat dump destroys both.
  * These files hold secrets (Pushover tokens, DB passwords). Writes must be
    atomic (temp + replace) so a crash cannot leave a half-written config, and
    the file mode must stay 0600.
  * Setting a key must never silently duplicate it (a duplicated key later in
    the file wins in most .env parsers, which produces a config that looks
    right in the editor and behaves differently at runtime).

Round-trip guarantee: loading and writing without changes is a no-op on
content. Unknown keys are preserved.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# KEY=value  (leading whitespace, optional `export`, optional quotes)
_KV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
COMMENT_PREFIXES = ("#", ";")


@dataclass
class EnvFile:
    """A parsed .env file that remembers its original shape."""

    path: Path
    lines: list[str] = field(default_factory=list)

    # -- construction ------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> EnvFile:
        p = Path(path)
        if not p.exists():
            return cls(path=p, lines=[])
        return cls(path=p, lines=p.read_text(encoding="utf-8").splitlines())

    @classmethod
    def from_example(cls, example: str | Path, target: str | Path) -> EnvFile:
        """Seed a new .env from .env.example (comments and all)."""
        ex = Path(example)
        tgt = Path(target)
        if not ex.exists():
            raise FileNotFoundError(f"template not found: {ex}")
        return cls(path=tgt, lines=ex.read_text(encoding="utf-8").splitlines())

    # -- queries -----------------------------------------------------------
    def keys(self) -> list[str]:
        out = []
        for line in self.lines:
            if line.lstrip().startswith(COMMENT_PREFIXES):
                continue
            m = _KV.match(line)
            if m:
                out.append(m.group(1))
        return out

    def get(self, key: str, default: str | None = None) -> str | None:
        """Last occurrence wins (matches dotenv semantics)."""
        value = default
        for line in self.lines:
            if line.lstrip().startswith(COMMENT_PREFIXES):
                continue
            m = _KV.match(line)
            if m and m.group(1) == key:
                value = _unquote(m.group(2))
        return value

    def duplicates(self) -> list[str]:
        seen: dict[str, int] = {}
        for k in self.keys():
            seen[k] = seen.get(k, 0) + 1
        return sorted(k for k, n in seen.items() if n > 1)

    def as_dict(self) -> dict[str, str]:
        return {k: (self.get(k) or "") for k in self.keys()}

    # -- mutation ----------------------------------------------------------
    def set(self, key: str, value: str) -> None:
        """Set key. Replaces the LAST occurrence in place (keeping position and
        any comments above it); appends if absent. Never creates a duplicate."""
        rendered = f"{key}={value}"
        idxs = [i for i, line in enumerate(self.lines) if _matches_key(line, key)]
        if idxs:
            self.lines[idxs[-1]] = rendered
            # Drop any earlier duplicates rather than leaving a shadowed key.
            for i in reversed(idxs[:-1]):
                del self.lines[i]
            return
        self.lines.append(rendered)

    def unset(self, key: str) -> bool:
        before = len(self.lines)
        self.lines = [line for line in self.lines if not _matches_key(line, key)]
        return len(self.lines) != before

    # -- persistence -------------------------------------------------------
    def save(self, mode: int = 0o600) -> Path:
        """Atomic write with restrictive permissions (secrets live here)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(self.lines) + "\n"
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".env.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.chmod(tmp, mode)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return self.path

    def backup(self, suffix: str = ".bak") -> Path | None:
        if not self.path.exists():
            return None
        dst = self.path.with_name(self.path.name + suffix)
        shutil.copy2(self.path, dst)
        return dst

    def render(self) -> str:
        return "\n".join(self.lines)


def _matches_key(line: str, key: str) -> bool:
    if line.lstrip().startswith(COMMENT_PREFIXES):
        return False
    m = _KV.match(line)
    return bool(m and m.group(1) == key)


def _unquote(raw: str) -> str:
    """Unquote and strip an inline comment — mirrors the app's own env parsing.

    The admin tooling and the application must interpret a `.env` line
    identically; otherwise `weirvern config validate` passes a value the worker
    then rejects (or vice versa).
    """
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        return raw[1:-1]
    # Trailing " # comment" is not part of an unquoted value.
    for marker in (" #", "\t#"):
        idx = raw.find(marker)
        if idx != -1:
            raw = raw[:idx]
            break
    return raw.strip()


def mask(value: str, visible: int = 4) -> str:
    """Mask a secret for display: show only the last few characters."""
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]


SECRET_HINTS = ("PASSWORD", "TOKEN", "KEY", "SECRET")


def is_secret(key: str) -> bool:
    up = key.upper()
    return any(h in up for h in SECRET_HINTS)
