"""Hash-linked audit / chain-of-custody log (spec section 16).

Each event stores the SHA-256 of its own fields concatenated with the previous
event's hash, forming a tamper-evident chain.  ``verify_audit_chain`` walks the
chain and reports the first broken link, if any.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import config
from .database import Database
from .hash_utils import sha256_text
from .utils import utc_now_iso


def compute_event_hash(
    event_utc: str,
    event_type: str,
    actor: str,
    evidence_id: Optional[int],
    description: str,
    previous_event_hash: str,
) -> str:
    """Deterministically hash a single audit event (spec section 16)."""
    payload = (
        f"{event_utc}|{event_type}|{actor}|{evidence_id if evidence_id is not None else ''}"
        f"|{description}|{previous_event_hash}"
    )
    return sha256_text(payload)


class AuditManager:
    """Append events to the tamper-evident audit chain."""

    def __init__(self, db: Database, actor: str = "ForenSight"):
        self.db = db
        self.actor = actor

    def record(
        self,
        event_type: str,
        description: str,
        evidence_id: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> str:
        """Record one event and return its event hash."""
        last = self.db.get_last_audit()
        previous_hash = last["event_hash"] if last else config.GENESIS_HASH
        event_utc = utc_now_iso()
        who = actor or self.actor
        event_hash = compute_event_hash(
            event_utc, event_type, who, evidence_id, description, previous_hash
        )
        self.db.insert_audit(
            {
                "event_utc": event_utc,
                "event_type": event_type,
                "actor": who,
                "evidence_id": evidence_id,
                "description": description,
                "previous_event_hash": previous_hash,
                "event_hash": event_hash,
            }
        )
        return event_hash


@dataclass
class ChainResult:
    valid: bool
    broken_event_id: Optional[int] = None
    message: str = ""


def verify_audit_chain(db: Database) -> ChainResult:
    """Walk the chain and confirm every link (spec section 16)."""
    rows = db.get_all_audit()
    previous_hash = config.GENESIS_HASH
    for row in rows:
        if row["previous_event_hash"] != previous_hash:
            return ChainResult(
                False, row["id"],
                f"Previous-hash mismatch at event {row['id']}.",
            )
        recomputed = compute_event_hash(
            row["event_utc"], row["event_type"], row["actor"],
            row["evidence_id"], row["description"], row["previous_event_hash"],
        )
        if recomputed != row["event_hash"]:
            return ChainResult(
                False, row["id"],
                f"Event hash mismatch at event {row['id']}.",
            )
        previous_hash = row["event_hash"]
    return ChainResult(True, None, "Audit Chain Valid")
