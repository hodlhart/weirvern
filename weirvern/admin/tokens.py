"""Per-token GUI credentials, each with its own role.

WHY THIS EXISTS. The GUI had exactly one token: `WEIRVERN_GUI_TOKEN`, a deployment-wide value read
from the environment at startup, admin-equivalent everywhere, and impossible to give to one person
without giving it to everyone. Accounts solved the human case, but automation still has no way to
hold a credential that is (a) individually revocable, (b) limited to reading, and (c) attributable
in the audit trail. A shared break-glass token is none of those.

WHAT A TOKEN IS, AND WHAT IT IS NOT.

  * A token is a CREDENTIAL, not an account. It has no username, no password, and no session; it
    cannot mint or revoke another token, and it cannot change its own role. Those actions require a
    signed-in admin session, because a token that could mint tokens is a token that can outlive its
    own revocation.
  * A token carries one of the two existing roles, `admin` or `viewer`. There is no third role and
    no per-token permission list: the permission model is users.ROLES, and a second copy of it here
    would be free to disagree.
  * The LEGACY `WEIRVERN_GUI_TOKEN` is untouched. It stays admin-equivalent, it is checked before
    this store, and a broken or unreadable token store cannot stop it from working. That is the
    break-glass property: the recovery credential must not depend on the thing it recovers from.

STORAGE: A CONFIGMAP (`weirvern-tokens`), NOT A SECRET -- the same trade the account store makes,
for the same reason. The GUI's ServiceAccount deliberately has no access to Secrets (so a
compromised pod cannot read the Pushover credentials), and widening that grant to hold credential
material would trade a proven guard for a weaker one. What is stored is a SHA-256 digest, not a
password: unlike a user password, a 256-bit random token is not guessable offline, so a slow KDF
buys nothing and would put tens of milliseconds on every request.

ONLY THE DIGEST IS STORED. The plaintext is generated in `create_token`, returned to the caller in
that one response, and never written, logged, or put in an audit row. The `prefix` field exists so
an operator can tell two tokens apart in a list: it is the literal first eight characters
(`wvt_` plus four random hex characters), i.e. an identifier, and the 32-byte secret half after it
is never stored in any form except its digest.

REVOCATION IS IMMEDIATE. `revoke()` writes the store and refreshes this object's cached view in the
same call, so the NEXT request presenting that token fails -- no restart, no TTL to wait out. The
GUI runs one replica (stated in users.py for the same reason); a second replica editing this store
is not a supported configuration, and revocation does not pretend to be a distributed operation.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# The store. A separate ConfigMap from weirvern-users so an account write can never touch tokens,
# and so each object's RBAC story is readable on its own.
TOKENS_CONFIGMAP = "weirvern-tokens"
TOKENS_KEY = "tokens.json"

# The public label shown in the list: `wvt_` plus four random hex characters. Everything after it
# is the secret and is never stored.
TOKEN_PREFIX_CHARS = 8
_TOKEN_MARKER = "wvt_"
_TOKEN_ID_BYTES = 6          # 12 hex characters; the revoke handle, not a credential
_SECRET_BYTES = 32           # 256 bits, the same order as the bootstrap password and a session
MAX_NAME_LEN = 48

# How often a successful authentication may rewrite the store to record `last_used_at`. A write per
# request would put a Kubernetes API call on the hot path; never writing would make the column a
# lie. Once a minute is the compromise, and a failed write must never fail the authentication.
_LAST_USED_PERSIST_S = 60.0


class TokenError(Exception):
    """A refused token operation, with a reason written for the operator."""


# ── the credential itself ──────────────────────────────────────────────────────────────


def hash_token(plaintext: str) -> str:
    """The SHA-256 digest of a token, lowercase hex.

    A plain hash, not a KDF. The input is 256 bits from `secrets`, so there is no dictionary to
    slow down; scrypt here would only add latency to every authenticated request.
    """
    return hashlib.sha256((plaintext or "").encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str, str]:
    """Mint one token. Returns `(plaintext, prefix, digest)`.

    THE PLAINTEXT LEAVES THIS FUNCTION AND IS NEVER STORED. The caller returns it in the create
    response and drops it; the store receives only the digest and the display prefix.
    """
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    # The identifier half is DERIVED FROM RANDOMNESS rather than from a counter, so two tokens
    # created in the same second cannot share a prefix and read as the same row.
    plaintext = f"{_TOKEN_MARKER}{secrets.token_hex(4)}_{secret}"
    return plaintext, plaintext[:TOKEN_PREFIX_CHARS], hash_token(plaintext)


def validate_name(name: str) -> str:
    """The token's label, or raise. A label is for a human, so it is only bounded and non-empty."""
    label = (name or "").strip()
    if not label:
        raise TokenError("a token needs a name, so the list can say what it is for")
    if len(label) > MAX_NAME_LEN:
        raise TokenError(f"a token name may be at most {MAX_NAME_LEN} characters")
    if any(ord(c) < 32 for c in label):
        raise TokenError("a token name may not contain control characters")
    return label


def _stamp() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── records ────────────────────────────────────────────────────────────────────────────


@dataclass
class TokenRecord:
    """One token. `token_hash` is credential material; `public()` never returns it."""

    token_id: str
    name: str
    role: str
    token_hash: str
    prefix: str
    created_at: str = ""
    created_by: str = ""
    last_used_at: str = ""
    revoked_at: str = ""
    revoked_by: str = ""

    @property
    def revoked(self) -> bool:
        return bool(self.revoked_at)

    def to_json(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id, "name": self.name, "role": self.role,
            "token_hash": self.token_hash, "prefix": self.prefix,
            "created_at": self.created_at, "created_by": self.created_by,
            "last_used_at": self.last_used_at, "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }

    @classmethod
    def from_json(cls, entry: dict[str, Any]) -> TokenRecord:
        return cls(
            token_id=str(entry.get("token_id") or ""),
            name=str(entry.get("name") or ""),
            role=str(entry.get("role") or "viewer"),
            token_hash=str(entry.get("token_hash") or ""),
            prefix=str(entry.get("prefix") or ""),
            created_at=str(entry.get("created_at") or ""),
            created_by=str(entry.get("created_by") or ""),
            last_used_at=str(entry.get("last_used_at") or ""),
            revoked_at=str(entry.get("revoked_at") or ""),
            revoked_by=str(entry.get("revoked_by") or ""),
        )

    def public(self) -> dict[str, Any]:
        """The record as the API returns it: the digest is NEVER included."""
        return {
            "token_id": self.token_id, "name": self.name, "role": self.role,
            "prefix": self.prefix, "created_at": self.created_at,
            "created_by": self.created_by, "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at, "revoked_by": self.revoked_by,
            "revoked": self.revoked,
        }


# ── the store ──────────────────────────────────────────────────────────────────────────


class TokenStore:
    """The tokens, read from and written to a ConfigMap through the cluster client.

    The client is duck-typed (`read` / `patch_data` / `create`), exactly the shape `UserStore` uses
    and the tests drive; the real one is `cluster_config.ClusterConfig` bound to
    `weirvern-tokens`.

    THE CACHE IS REFRESHED BY EVERY WRITE MADE THROUGH THIS OBJECT, which is what makes revocation
    bite on the next request. Reads are served from the cache so an authenticated request does not
    touch the Kubernetes API. A failed read is NOT cached for the life of the process -- the same
    F090 defect the account store documents: "degrade while unreadable", not "until a restart".
    """

    def __init__(self, client) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._records: list[TokenRecord] = []
        self._loaded = False
        self._last_used_flush = 0.0
        # Tri-state, identical to UserStore: True = exists, False = confirmed absent, None = the
        # read failed and absence could not be confirmed (so a create must not invent a document).
        self.exists: bool | None = False

    # -- read ------------------------------------------------------------------

    def load(self) -> list[TokenRecord]:
        """Read the store once. Sets `exists`; an unreadable store is an empty list + None."""
        raw = ""
        exists: bool | None = None
        readable = False
        try:
            data = self._client.read()
            readable = True
            if isinstance(data, dict):
                exists = True
                raw = str(data.get(TOKENS_KEY) or "")
        except Exception as exc:  # noqa: BLE001
            from weirvern.admin.cluster_config import NotFoundError  # noqa: PLC0415

            if isinstance(exc, NotFoundError):
                exists = False
                readable = True
            else:
                exists = None
            logger.info("token store read: exists=%s (%s)", exists, exc)
        records: list[TokenRecord] = []
        if raw.strip():
            try:
                doc = json.loads(raw)
                for entry in (doc.get("tokens") or []):
                    if isinstance(entry, dict) and entry.get("token_id"):
                        records.append(TokenRecord.from_json(entry))
            except ValueError as exc:
                logger.warning("token store is not valid JSON; refusing to guess at tokens: %s", exc)
                records = []
        with self._lock:
            self._records = records
            self._loaded = readable
            self.exists = exists
        if not readable:
            logger.warning(
                "the token store could not be read, so per-token credentials will not authenticate "
                "until it answers; the break-glass operator token is unaffected (%s)", self.exists,
            )
        return list(records)

    def snapshot(self) -> list[TokenRecord]:
        """The cached records. Loads once if nothing has been read yet."""
        with self._lock:
            if self._loaded:
                return list(self._records)
        return self.load()

    def has_tokens(self) -> bool:
        """Whether any LIVE token exists. Used for reporting, never as the authorization decision."""
        return any(not t.revoked for t in self.snapshot())

    def find(self, token_id: str) -> TokenRecord | None:
        wanted = (token_id or "").strip()
        for entry in self.snapshot():
            if entry.token_id == wanted:
                return entry
        return None

    def public_tokens(self) -> list[dict[str, Any]]:
        return [t.public() for t in self.snapshot()]

    # -- write -----------------------------------------------------------------

    def _persist(self, records: list[TokenRecord]) -> None:
        """Write the whole document, then refresh the cache from what we wrote."""
        doc = json.dumps({"tokens": [t.to_json() for t in records]}, indent=1)
        if self.exists:
            self._client.patch_data({TOKENS_KEY: doc})
        else:
            try:
                self._client.create({TOKENS_KEY: doc})
                self.exists = True
            except Exception:  # noqa: BLE001
                # A create refused because the object already exists is fine; patch it instead.
                self._client.patch_data({TOKENS_KEY: doc})
                self.exists = True
        with self._lock:
            self._records = list(records)
            self._loaded = True

    def create_token(self, name: str, role: str, *, created_by: str = "") -> tuple[TokenRecord, str]:
        """Mint a token and return `(record, plaintext)`. The plaintext is NOT stored."""
        from weirvern.admin import users as users_mod  # noqa: PLC0415

        label = validate_name(name)
        if role not in users_mod.ROLES:
            raise TokenError(f"role must be one of {', '.join(users_mod.ROLES)}")
        records = self.snapshot()
        plaintext, prefix, digest = generate_token()
        now = _stamp()
        record = TokenRecord(
            token_id=secrets.token_hex(_TOKEN_ID_BYTES), name=label, role=role,
            token_hash=digest, prefix=prefix, created_at=now, created_by=created_by,
        )
        self._persist(records + [record])
        logger.info("created a %s token named %r (prefix %s)", role, label, prefix)
        return record, plaintext

    def revoke(self, token_id: str, *, revoked_by: str = "") -> TokenRecord:
        """Revoke one token. The NEXT request presenting it is refused.

        IDEMPOTENT: revoking an already-revoked token returns the record rather than raising. The
        UI reloads after a write, and a second click must not read as a failure.
        """
        records = self.snapshot()
        target = next((t for t in records if t.token_id == (token_id or "").strip()), None)
        if target is None:
            raise TokenError("no token with that id")
        if not target.revoked:
            target.revoked_at = _stamp()
            target.revoked_by = revoked_by
            self._persist(records)
            logger.info("revoked token %r (%s)", target.name, target.token_id)
        return target

    # -- authentication ---------------------------------------------------------

    def authenticate(self, presented: str) -> TokenRecord | None:
        """The live record matching `presented`, or None. Updates `last_used_at` on a match.

        EVERY LOOKUP HASHES, AND EVERY RECORD IS COMPARED, including after a match: the loop does
        not break, so the work does not vary with the position of the matching token.
        """
        value = (presented or "").strip()
        if not value:
            return None
        digest = hash_token(value)
        match: TokenRecord | None = None
        for record in self.snapshot():
            if record.revoked:
                continue
            if hmac.compare_digest(record.token_hash, digest):
                match = record
        if match is None:
            return None
        match.last_used_at = _stamp()
        self._persist_last_used()
        return match

    def _persist_last_used(self) -> None:
        """Write `last_used_at` back at most once a minute. A failure must not fail the request.

        The token is already authenticated by the time this runs; losing the timestamp is a
        cosmetic loss, while an exception here would turn a valid credential into a 500.
        """
        now = time.monotonic()
        with self._lock:
            if now - self._last_used_flush < _LAST_USED_PERSIST_S:
                return
            self._last_used_flush = now
            records = list(self._records)
        try:
            self._persist(records)
        except Exception as exc:  # noqa: BLE001
            logger.debug("could not record token last-used time: %s", exc)
