"""
QuorumLog — storage.py

SQLite (WAL mode) persistence for personal logs, witnessed (author, seq) records,
receipts, fraud proofs (doubles as a permanent author blacklist) and the peer cache.

All multi-statement operations run inside BEGIN IMMEDIATE transactions, so a crash
between statements can never leave a half-applied state. `record_witness` is the
atomic heart of the conflict detector:

    ("OK",   None)            newly inserted, or identical hash already present
    ("FRAUD", existing)       a DIFFERENT hash already occupies (author, seq)
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
from typing import Any, List, Optional, Tuple

from crypto import (DEFAULT_DIFFICULTY, Entry, FraudProof, Receipt, canonical_json,
                    verify_entry)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS local_entries (
    author     TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (author, seq)
);
CREATE TABLE IF NOT EXISTS witnessed (
    author     TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (author, seq)
);
CREATE TABLE IF NOT EXISTS receipts (
    entry_hash   TEXT NOT NULL,
    witness      TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (entry_hash, witness)
);
CREATE TABLE IF NOT EXISTS fraud_proofs (
    accused    TEXT PRIMARY KEY,
    proof_json TEXT NOT NULL,
    proof_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
    node_id   TEXT PRIMARY KEY,
    host      TEXT NOT NULL,
    port      INTEGER NOT NULL,
    pubkey    TEXT NOT NULL,
    last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_witnessed_author ON witnessed(author, seq);
"""


class StorageError(RuntimeError):
    """Raised when a local-chain append would violate chain integrity."""


class Storage:
    """Single SQLite connection guarded by an RLock; safe across threads/tasks."""

    def __init__(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---------------------------------------------------------------- util

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            with contextlib.suppress(sqlite3.Error):
                self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.close()

    def _entry_from_row(self, row: sqlite3.Row) -> Entry:
        return Entry.from_dict(json.loads(row["entry_json"]))

    # ------------------------------------------------------- local chain

    def append_local_entry(self, entry: Entry,
                           difficulty: int = DEFAULT_DIFFICULTY) -> None:
        """Atomically append to OUR personal chain, enforcing strict linkage."""
        with self._lock:
            ok, reason = verify_entry(entry, difficulty)
            if not ok:
                raise StorageError(f"refusing to append invalid entry: {reason}")
            cur = self._db.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                row = cur.execute(
                    "SELECT seq, entry_hash FROM local_entries WHERE author=? "
                    "ORDER BY seq DESC LIMIT 1", (entry.author,)).fetchone()
                if row is None:
                    if entry.seq != 0:
                        raise StorageError("first local entry must have seq 0")
                else:
                    if entry.seq != row["seq"] + 1:
                        raise StorageError(
                            f"non-consecutive seq: have {row['seq']}, got {entry.seq}")
                    if entry.prev_hash != row["entry_hash"]:
                        raise StorageError("prev_hash does not link to local chain head")
                cur.execute(
                    "INSERT INTO local_entries(author, seq, entry_hash, entry_json) "
                    "VALUES(?,?,?,?)",
                    (entry.author, entry.seq, entry.entry_hash,
                     canonical_json(entry.to_dict()).decode("utf-8")))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def last_local(self, author: str) -> Optional[Entry]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM local_entries WHERE author=? ORDER BY seq DESC LIMIT 1",
                (author,)).fetchone()
        return self._entry_from_row(row) if row else None

    def verify_local_chain(self, author: str,
                           difficulty: int = DEFAULT_DIFFICULTY) -> Tuple[bool, str]:
        """Recompute every hash/signature/link; halt immediately on any tampered byte."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, entry_hash, entry_json FROM local_entries WHERE author=? "
                "ORDER BY seq ASC", (author,)).fetchall()
        if not rows:
            return True, "empty"
        if rows[0]["seq"] != 0:
            return False, "chain does not start at seq 0"
        prev_hash: Optional[str] = None
        for i, row in enumerate(rows):
            try:
                entry = self._entry_from_row(row)
            except Exception as exc:
                return False, f"seq {row['seq']}: unparseable entry ({exc})"
            if entry.author != author:
                return False, f"seq {row['seq']}: author mismatch"
            if entry.seq != i:
                return False, f"seq gap/overlap at position {i}"
            if entry.entry_hash != row["entry_hash"]:
                return False, f"seq {entry.seq}: stored entry_hash does not match content"
            ok, reason = verify_entry(entry, difficulty)
            if not ok:
                return False, f"seq {entry.seq}: invalid entry ({reason})"
            if prev_hash is not None and entry.prev_hash != prev_hash:
                return False, f"seq {entry.seq}: chain break (prev_hash mismatch)"
            prev_hash = entry.entry_hash
        return True, "ok"

    # ----------------------------------------------- witnessed (foreign) logs

    def record_witness(self, entry: Entry) -> Tuple[str, Optional[Entry]]:
        """Atomic insert-or-conflict check keyed on (author, seq). See module docstring."""
        entry_hash = entry.entry_hash
        entry_json = canonical_json(entry.to_dict()).decode("utf-8")
        with self._lock:
            cur = self._db.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                row = cur.execute(
                    "SELECT entry_hash, entry_json FROM witnessed WHERE author=? AND seq=?",
                    (entry.author, entry.seq)).fetchone()
                if row is not None:
                    self._db.commit()
                    if row["entry_hash"] == entry_hash:
                        return "OK", None            # idempotent retry
                    return "FRAUD", Entry.from_dict(json.loads(row["entry_json"]))
                cur.execute(
                    "INSERT INTO witnessed(author, seq, entry_hash, entry_json) "
                    "VALUES(?,?,?,?)",
                    (entry.author, entry.seq, entry_hash, entry_json))
                self._db.commit()
                return "OK", None
            except Exception:
                self._db.rollback()
                raise

    def last_witnessed(self, author: str) -> Optional[Entry]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM witnessed WHERE author=? ORDER BY seq DESC LIMIT 1",
                (author,)).fetchone()
        return self._entry_from_row(row) if row else None

    def chain_entries(self, author: str, after_seq: int, limit: int = 48) -> List[Entry]:
        """Merged (local ∪ witnessed) chain slices for SYNC responses, ordered by seq."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, entry_json FROM ("
                "  SELECT seq, entry_json FROM local_entries WHERE author=? AND seq>? "
                "  UNION ALL SELECT seq, entry_json FROM witnessed WHERE author=? AND seq>?"
                ") GROUP BY seq ORDER BY seq ASC LIMIT ?",
                (author, after_seq, author, after_seq, limit)).fetchall()
        out: List[Entry] = []
        for row in rows:
            try:
                out.append(Entry.from_dict(json.loads(row["entry_json"])))
            except Exception:
                continue
        return out

    # ---------------------------------------------------------------- receipts

    def add_receipt(self, receipt: Receipt) -> bool:
        receipt_json = canonical_json(receipt.to_dict()).decode("utf-8")
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO receipts(entry_hash, witness, receipt_json) "
                "VALUES(?,?,?)",
                (receipt.entry_hash, receipt.witness, receipt_json))
            self._db.commit()
            return cur.rowcount > 0

    def receipts_for(self, entry_hash: str) -> List[Receipt]:
        with self._lock:
            rows = self._db.execute(
                "SELECT receipt_json FROM receipts WHERE entry_hash=?", (entry_hash,)).fetchall()
        out: List[Receipt] = []
        for row in rows:
            try:
                out.append(Receipt.from_dict(json.loads(row["receipt_json"])))
            except Exception:
                continue
        return out

    # ----------------------------------------------------- fraud proofs / blacklist

    def add_fraud_proof(self, proof: FraudProof) -> bool:
        """Permanently blacklist the accused author. Idempotent per accused pubkey."""
        proof_json = canonical_json(proof.to_dict()).decode("utf-8")
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO fraud_proofs(accused, proof_json, proof_hash, created_at) "
                "VALUES(?,?,?,?)",
                (proof.accused, proof_json, proof.proof_hash, _now()))
            self._db.commit()
            return cur.rowcount > 0

    def is_blacklisted(self, pubkey: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM fraud_proofs WHERE accused=?", (pubkey,)).fetchone()
        return row is not None

    def get_fraud_proof(self, accused: str) -> Optional[FraudProof]:
        with self._lock:
            row = self._db.execute(
                "SELECT proof_json FROM fraud_proofs WHERE accused=?", (accused,)).fetchone()
        if not row:
            return None
        try:
            return FraudProof.from_dict(json.loads(row["proof_json"]))
        except Exception:
            return None

    # ---------------------------------------------------------------- peers

    def upsert_peer(self, node_id: str, host: str, port: int, pubkey: str,
                    last_seen: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO peers(node_id, host, port, pubkey, last_seen) VALUES(?,?,?,?,?) "
                "ON CONFLICT(node_id) DO UPDATE SET host=excluded.host, port=excluded.port, "
                "pubkey=excluded.pubkey, last_seen=excluded.last_seen",
                (node_id, host, port, pubkey, last_seen))
            self._db.commit()

    def get_peers(self, limit: int = 256) -> List[Tuple[str, str, int, str, float]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT node_id, host, port, pubkey, last_seen FROM peers "
                "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [(r["node_id"], r["host"], r["port"], r["pubkey"], r["last_seen"])
                for r in rows]


def _now() -> float:
    import time
    return time.time()