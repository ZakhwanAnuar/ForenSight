"""SQLite persistence layer (spec section 15).

All queries are parameterised.  The class exposes small, purpose-built
helpers so the rest of the application never builds SQL by string formatting.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

from . import config

# ---------------------------------------------------------------------------
# Schema (exactly as specified in section 15)
# ---------------------------------------------------------------------------
SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS case_info (
        case_id TEXT PRIMARY KEY,
        case_name TEXT NOT NULL,
        examiner_name TEXT NOT NULL,
        examiner_id TEXT NOT NULL,
        organization TEXT,
        created_utc TEXT NOT NULL,
        closed_utc TEXT,
        case_root_path TEXT NOT NULL,
        case_status TEXT NOT NULL,
        final_report_path TEXT,
        final_report_sha256 TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_sources (
        evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_name TEXT NOT NULL,
        source_path TEXT NOT NULL,
        source_type TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        sha256_hash TEXT NOT NULL,
        imported_utc TEXT NOT NULL,
        description TEXT,
        integrity_status TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS carved_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        file_name TEXT NOT NULL,
        file_format TEXT NOT NULL,
        file_path TEXT NOT NULL,
        source_offset INTEGER NOT NULL,
        source_offset_hex TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        sha256_hash TEXT NOT NULL,
        recovery_method TEXT NOT NULL,
        is_deleted INTEGER NOT NULL DEFAULT 1,
        allocation_status TEXT DEFAULT 'Unknown',
        is_suspicious INTEGER NOT NULL DEFAULT 0,
        is_valid INTEGER NOT NULL DEFAULT 0,
        validation_message TEXT,
        created_utc TEXT NOT NULL,
        FOREIGN KEY(evidence_id) REFERENCES evidence_sources(evidence_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS exif_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        carved_evidence_id INTEGER NOT NULL,
        camera_make TEXT,
        camera_model TEXT,
        capture_datetime TEXT,
        software TEXT,
        gps_latitude TEXT,
        gps_longitude TEXT,
        orientation TEXT,
        metadata_json TEXT,
        extracted_utc TEXT NOT NULL,
        FOREIGN KEY(carved_evidence_id) REFERENCES carved_evidence(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS image_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        carved_evidence_id INTEGER NOT NULL,
        jpeg_quality_estimate REAL,
        jpeg_quantization_summary TEXT,
        file_type_match INTEGER,
        thumbnail_path TEXT,
        assessment TEXT,
        manipulation_score INTEGER,
        provenance TEXT,
        ml_ai_probability REAL,
        analyzed_utc TEXT NOT NULL,
        FOREIGN KEY(carved_evidence_id) REFERENCES carved_evidence(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        carved_evidence_id INTEGER NOT NULL,
        priority TEXT NOT NULL,
        reason TEXT,
        examiner_note TEXT,
        created_utc TEXT NOT NULL,
        updated_utc TEXT,
        FOREIGN KEY(carved_evidence_id) REFERENCES carved_evidence(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_utc TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        evidence_id INTEGER,
        description TEXT NOT NULL,
        previous_event_hash TEXT,
        event_hash TEXT NOT NULL,
        FOREIGN KEY(evidence_id) REFERENCES carved_evidence(id)
    );
    """,
]


class Database:
    """Thin wrapper around a single-case SQLite connection."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after a case was first created (safe on new
        databases, where the table does not exist yet)."""
        try:
            cols = [r[1] for r in self.conn.execute("PRAGMA table_info(image_analysis)")]
            if cols and "manipulation_score" not in cols:
                self.conn.execute(
                    "ALTER TABLE image_analysis ADD COLUMN manipulation_score INTEGER")
                self.conn.commit()
            if cols and "provenance" not in cols:
                self.conn.execute(
                    "ALTER TABLE image_analysis ADD COLUMN provenance TEXT")
                self.conn.commit()
            if cols and "ml_ai_probability" not in cols:
                self.conn.execute(
                    "ALTER TABLE image_analysis ADD COLUMN ml_ai_probability REAL")
                self.conn.commit()
            ccols = [r[1] for r in self.conn.execute(
                "PRAGMA table_info(carved_evidence)")]
            if ccols and "allocation_status" not in ccols:
                self.conn.execute("ALTER TABLE carved_evidence "
                                  "ADD COLUMN allocation_status TEXT DEFAULT 'Unknown'")
                self.conn.commit()
        except sqlite3.Error:
            pass

    # -- lifecycle ---------------------------------------------------------
    def initialize_schema(self) -> None:
        cur = self.conn.cursor()
        for statement in SCHEMA_STATEMENTS:
            cur.execute(statement)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

    def commit(self) -> None:
        self.conn.commit()

    # -- generic helpers ---------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, tuple(params))
        return cur

    def query_all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, tuple(params)).fetchall())

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        return self.conn.execute(sql, tuple(params)).fetchone()

    # -- case_info ---------------------------------------------------------
    def insert_case_info(self, data: dict) -> None:
        self.conn.execute(
            """
            INSERT INTO case_info
                (case_id, case_name, examiner_name, examiner_id, organization,
                 created_utc, closed_utc, case_root_path, case_status,
                 final_report_path, final_report_sha256)
            VALUES (:case_id, :case_name, :examiner_name, :examiner_id,
                    :organization, :created_utc, :closed_utc, :case_root_path,
                    :case_status, :final_report_path, :final_report_sha256)
            """,
            data,
        )
        self.conn.commit()

    def get_case_info(self) -> Optional[sqlite3.Row]:
        return self.query_one("SELECT * FROM case_info LIMIT 1")

    def update_case_status(self, case_id: str, status: str, closed_utc: str | None = None) -> None:
        self.conn.execute(
            "UPDATE case_info SET case_status = ?, closed_utc = ? WHERE case_id = ?",
            (status, closed_utc, case_id),
        )
        self.conn.commit()

    def set_final_report(self, case_id: str, path: str, sha256: str) -> None:
        self.conn.execute(
            "UPDATE case_info SET final_report_path = ?, final_report_sha256 = ? WHERE case_id = ?",
            (path, sha256, case_id),
        )
        self.conn.commit()

    # -- evidence_sources --------------------------------------------------
    def insert_evidence_source(self, data: dict) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO evidence_sources
                (evidence_name, source_path, source_type, file_size_bytes,
                 sha256_hash, imported_utc, description, integrity_status)
            VALUES (:evidence_name, :source_path, :source_type, :file_size_bytes,
                    :sha256_hash, :imported_utc, :description, :integrity_status)
            """,
            data,
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_evidence_sources(self) -> list[sqlite3.Row]:
        return self.query_all("SELECT * FROM evidence_sources ORDER BY evidence_id")

    def get_evidence_source(self, evidence_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM evidence_sources WHERE evidence_id = ?", (evidence_id,)
        )

    def update_evidence_integrity(self, evidence_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE evidence_sources SET integrity_status = ? WHERE evidence_id = ?",
            (status, evidence_id),
        )
        self.conn.commit()

    # -- carved_evidence ---------------------------------------------------
    def insert_carved(self, data: dict) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO carved_evidence
                (evidence_id, file_name, file_format, file_path, source_offset,
                 source_offset_hex, file_size_bytes, sha256_hash, recovery_method,
                 is_deleted, allocation_status, is_suspicious, is_valid,
                 validation_message, created_utc)
            VALUES (:evidence_id, :file_name, :file_format, :file_path,
                    :source_offset, :source_offset_hex, :file_size_bytes,
                    :sha256_hash, :recovery_method, :is_deleted,
                    :allocation_status, :is_suspicious,
                    :is_valid, :validation_message,
                    :created_utc)
            """,
            data,
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_carved(self, carved_id: int) -> Optional[sqlite3.Row]:
        return self.query_one("SELECT * FROM carved_evidence WHERE id = ?", (carved_id,))

    def carved_exists(self, evidence_id, source_offset, sha256) -> bool:
        """True if this exact carve (same source offset + content) already exists.

        Makes re-running a carve idempotent - the same image is never stored
        twice.
        """
        if evidence_id is None:
            row = self.query_one(
                "SELECT 1 FROM carved_evidence WHERE evidence_id IS NULL "
                "AND source_offset = ? AND sha256_hash = ? LIMIT 1",
                (source_offset, sha256))
        else:
            row = self.query_one(
                "SELECT 1 FROM carved_evidence WHERE evidence_id = ? "
                "AND source_offset = ? AND sha256_hash = ? LIMIT 1",
                (evidence_id, source_offset, sha256))
        return row is not None

    def get_all_carved(self) -> list[sqlite3.Row]:
        return self.query_all("SELECT * FROM carved_evidence ORDER BY id")

    # -- exif_metadata -----------------------------------------------------
    def upsert_exif(self, data: dict) -> None:
        self.conn.execute(
            "DELETE FROM exif_metadata WHERE carved_evidence_id = ?",
            (data["carved_evidence_id"],),
        )
        self.conn.execute(
            """
            INSERT INTO exif_metadata
                (carved_evidence_id, camera_make, camera_model, capture_datetime,
                 software, gps_latitude, gps_longitude, orientation, metadata_json,
                 extracted_utc)
            VALUES (:carved_evidence_id, :camera_make, :camera_model,
                    :capture_datetime, :software, :gps_latitude, :gps_longitude,
                    :orientation, :metadata_json, :extracted_utc)
            """,
            data,
        )
        self.conn.commit()

    def get_exif(self, carved_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM exif_metadata WHERE carved_evidence_id = ?", (carved_id,)
        )

    # -- image_analysis ----------------------------------------------------
    def upsert_image_analysis(self, data: dict) -> None:
        self.conn.execute(
            "DELETE FROM image_analysis WHERE carved_evidence_id = ?",
            (data["carved_evidence_id"],),
        )
        self.conn.execute(
            """
            INSERT INTO image_analysis
                (carved_evidence_id,
                 jpeg_quality_estimate, jpeg_quantization_summary, file_type_match,
                 thumbnail_path, assessment, manipulation_score, provenance,
                 ml_ai_probability, analyzed_utc)
            VALUES (:carved_evidence_id,
                    :jpeg_quality_estimate,
                    :jpeg_quantization_summary, :file_type_match, :thumbnail_path,
                    :assessment, :manipulation_score, :provenance,
                    :ml_ai_probability, :analyzed_utc)
            """,
            data,
        )
        self.conn.commit()

    def get_image_analysis(self, carved_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM image_analysis WHERE carved_evidence_id = ?", (carved_id,)
        )

    # -- bookmarks ---------------------------------------------------------
    def upsert_bookmark(self, data: dict) -> None:
        existing = self.query_one(
            "SELECT id FROM bookmarks WHERE carved_evidence_id = ?",
            (data["carved_evidence_id"],),
        )
        if existing:
            self.conn.execute(
                """
                UPDATE bookmarks
                   SET priority = :priority, reason = :reason,
                       examiner_note = :examiner_note, updated_utc = :updated_utc
                 WHERE carved_evidence_id = :carved_evidence_id
                """,
                data,
            )
        else:
            self.conn.execute(
                """
                INSERT INTO bookmarks
                    (carved_evidence_id, priority, reason, examiner_note,
                     created_utc, updated_utc)
                VALUES (:carved_evidence_id, :priority, :reason, :examiner_note,
                        :created_utc, :updated_utc)
                """,
                data,
            )
        self.conn.commit()

    def get_bookmark(self, carved_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM bookmarks WHERE carved_evidence_id = ?", (carved_id,)
        )

    def remove_bookmark(self, carved_id: int) -> None:
        self.conn.execute(
            "DELETE FROM bookmarks WHERE carved_evidence_id = ?", (carved_id,)
        )
        self.conn.commit()

    def get_all_bookmarks(self) -> list[sqlite3.Row]:
        return self.query_all(
            """
            SELECT b.*, c.file_name, c.file_format
              FROM bookmarks b
              JOIN carved_evidence c ON c.id = b.carved_evidence_id
             ORDER BY CASE b.priority
                        WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,
                      b.created_utc
            """
        )

    # -- audit_log ---------------------------------------------------------
    def insert_audit(self, data: dict) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO audit_log
                (event_utc, event_type, actor, evidence_id, description,
                 previous_event_hash, event_hash)
            VALUES (:event_utc, :event_type, :actor, :evidence_id, :description,
                    :previous_event_hash, :event_hash)
            """,
            data,
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_last_audit(self) -> Optional[sqlite3.Row]:
        return self.query_one("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1")

    def get_all_audit(self) -> list[sqlite3.Row]:
        return self.query_all("SELECT * FROM audit_log ORDER BY id")

    # -- dashboard aggregates ---------------------------------------------
    def count(self, sql: str, params: Iterable[Any] = ()) -> int:
        row = self.query_one(sql, params)
        return int(row[0]) if row else 0
