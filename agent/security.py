from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from uuid import uuid4

ALLOWED_ACTIONS = frozenset({"APPROVE", "SHORT_PAY", "HOLD"})
# action -> statuses the ERP row may carry (status must agree with the approved action)
ACTION_STATUS = {
    "APPROVE": frozenset({"APPROVE", "APPROVED"}),
    "SHORT_PAY": frozenset({"SHORT_PAY"}),
    "HOLD": frozenset({"HOLD", "ON_HOLD"}),
}
MAX_JOB_TTL_SECONDS = 300

ENVELOPE_KEYS = frozenset(
    {"type", "job_id", "device_id", "action", "approval_id", "payload", "expires_at", "signature"}
)
PAYLOAD_REQUIRED = frozenset({"po_number", "vendor_name", "invoice_number", "payable", "status"})
PAYLOAD_ALLOWED = PAYLOAD_REQUIRED | {"variance"}

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")
VENDOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,&()'\-/]{0,119}$")
MONEY_RE = re.compile(r"^\d{1,12}(\.\d{1,2})?$")
SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class SecurityValidationError(Exception):
    """Envelope failed authentication or policy checks."""


def canonical_json(data: dict[str, Any]) -> bytes:
    """CONTRACT (must match the cloud byte-for-byte):
    json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ensure_ascii=True so that Python's default escaping on both sides agrees for non-ASCII text.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_hmac_sha256(secret: str, envelope_without_sig: dict[str, Any]) -> str:
    if not secret:
        raise SecurityValidationError("Missing device HMAC secret")
    return hmac.new(secret.encode("utf-8"), canonical_json(envelope_without_sig), hashlib.sha256).hexdigest()


def verify_hmac_sha256(secret: str, envelope: dict[str, Any]) -> bool:
    sig = envelope.get("signature")
    if not isinstance(sig, str) or not SIG_RE.match(sig):
        return False
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    try:
        expected = compute_hmac_sha256(secret, unsigned)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(sig.lower().encode(), expected.lower().encode())


class ReplayStore:
    """SQLite store of processed job_ids. claim() is atomic; results are kept so a
    duplicate delivery re-sends the original result instead of re-executing."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS processed_jobs (
                       job_id TEXT PRIMARY KEY,
                       device_id TEXT NOT NULL,
                       action TEXT NOT NULL,
                       status TEXT NOT NULL,
                       result_json TEXT,
                       processed_at INTEGER NOT NULL,
                       updated_at INTEGER NOT NULL)"""
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        return _ConnCtx(conn)

    def claim(self, job_id: str, device_id: str, action: str) -> bool:
        """True only for the first caller ever to claim this job_id."""
        now = int(time.time())
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO processed_jobs "
                "(job_id, device_id, action, status, processed_at, updated_at) VALUES (?,?,?,?,?,?)",
                (job_id, device_id, action, "IN_PROGRESS", now, now),
            )
            return cur.rowcount == 1

    def finish(self, job_id: str, status: str, result: dict[str, Any] | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE processed_jobs SET status=?, result_json=?, updated_at=? WHERE job_id=?",
                (status, json.dumps(result) if result is not None else None, int(time.time()), job_id),
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT status, result_json FROM processed_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            return None
        return {"status": row[0], "result": json.loads(row[1]) if row[1] else None}

    def has_seen(self, job_id: str) -> bool:
        return self.get(job_id) is not None


class _ConnCtx:
    """sqlite3 context manager that really closes the connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._c = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._c

    def __exit__(self, *exc: Any) -> None:
        self._c.close()


def validate_execution_job(
    envelope: dict[str, Any],
    *,
    expected_device_id: str,
    hmac_secret: str,
    replay_store: ReplayStore | None = None,  # kept for API compat; replay is handled by claim()
    now_ts: int | None = None,
) -> dict[str, Any]:
    """Authenticate FIRST (signature), then apply policy. Replay is enforced by ReplayStore.claim()."""
    if now_ts is None:
        now_ts = int(time.time())
    if not isinstance(envelope, dict):
        raise SecurityValidationError("Envelope must be a JSON object")
    if envelope.get("type") != "EXECUTE":
        raise SecurityValidationError("Invalid message type")

    keys = set(envelope.keys())
    if keys != ENVELOPE_KEYS:
        raise SecurityValidationError(
            f"Envelope fields invalid: missing={sorted(ENVELOPE_KEYS - keys)} unexpected={sorted(keys - ENVELOPE_KEYS)}"
        )

    if not verify_hmac_sha256(hmac_secret, envelope):
        raise SecurityValidationError("HMAC-SHA256 signature verification failed")

    job_id, device_id = envelope["job_id"], envelope["device_id"]
    action, approval_id = envelope["action"], envelope["approval_id"]
    expires_at, payload = envelope["expires_at"], envelope["payload"]

    for name, val in (("job_id", job_id), ("device_id", device_id), ("approval_id", approval_id)):
        if not isinstance(val, str) or not ID_RE.match(val):
            raise SecurityValidationError(f"Invalid identifier: {name}")
    if device_id != expected_device_id:
        raise SecurityValidationError("Device mismatch")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise SecurityValidationError(f"Disallowed action: {action!r}")

    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise SecurityValidationError("expires_at must be a UNIX integer timestamp")
    if expires_at <= now_ts:
        raise SecurityValidationError("Execution job has expired")
    if expires_at - now_ts > MAX_JOB_TTL_SECONDS:
        raise SecurityValidationError("Execution job lifetime exceeds permitted maximum")

    if not isinstance(payload, dict):
        raise SecurityValidationError("Payload must be a JSON object")
    pkeys = set(payload.keys())
    if not PAYLOAD_REQUIRED <= pkeys or not pkeys <= PAYLOAD_ALLOWED:
        raise SecurityValidationError(
            f"Payload fields invalid: missing={sorted(PAYLOAD_REQUIRED - pkeys)} unexpected={sorted(pkeys - PAYLOAD_ALLOWED)}"
        )

    for k in ("po_number", "invoice_number"):
        if not isinstance(payload[k], str) or not ID_RE.match(payload[k]):
            raise SecurityValidationError(f"Invalid payload identifier: {k}")
    if not isinstance(payload["vendor_name"], str) or not VENDOR_RE.match(payload["vendor_name"]):
        raise SecurityValidationError("Invalid payload.vendor_name")
    if not isinstance(payload["status"], str) or payload["status"] not in ACTION_STATUS[action]:
        raise SecurityValidationError("payload.status does not match approved action")

    def money(field: str, value: Any) -> Decimal:
        if not isinstance(value, str) or not MONEY_RE.match(value):
            raise SecurityValidationError(f"Invalid monetary amount in payload.{field}")
        try:
            return Decimal(value).quantize(Decimal("0.01"))
        except InvalidOperation as exc:
            raise SecurityValidationError(f"Invalid monetary amount in payload.{field}") from exc

    payable = money("payable", payload["payable"])
    variance = money("variance", payload.get("variance", "0.00"))

    return {
        "job_id": job_id,
        "device_id": device_id,
        "action": action,
        "approval_id": approval_id,
        "expires_at": expires_at,
        "payload": {
            "po_number": payload["po_number"],
            "vendor_name": payload["vendor_name"],
            "invoice_number": payload["invoice_number"],
            "payable": str(payable),
            "status": payload["status"],
            "variance": str(variance),
        },
    }


class HashChainAuditLog:
    """Append-only JSONL, SHA-256 hash-chained. Tamper-EVIDENT only (not a signature, not tamper-proof)."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return self.GENESIS_HASH
        last = ""
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line.strip()
        if not last:
            return self.GENESIS_HASH
        try:
            h = json.loads(last).get("current_hash")
        except json.JSONDecodeError as exc:
            raise RuntimeError("Audit log tail is corrupt; refusing to extend the chain") from exc
        if not isinstance(h, str) or not SIG_RE.match(h):
            raise RuntimeError("Audit log tail has no valid current_hash; refusing to extend the chain")
        return h

    def append(
        self,
        *,
        job_id: str,
        device_id: str,
        action: str,
        execution_status: str,
        detail: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": f"EVT-{uuid4().hex[:12]}",
            "job_id": job_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "action": action,
            "execution_status": execution_status,
            "detail": detail,
            "extra": extra or {},
            "prev_hash": self._last_hash(),
        }
        event["current_hash"] = hashlib.sha256(canonical_json(event)).hexdigest()
        with self.log_path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return event

    def verify_chain(self) -> tuple[bool, str]:
        if not self.log_path.exists():
            return True, "Empty log"
        expected_prev, count = self.GENESIS_HASH, 0
        with self.log_path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                count += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"Malformed JSON at line {idx}"
                if rec.get("prev_hash") != expected_prev:
                    return False, f"Broken prev_hash link at line {idx}"
                body = {k: v for k, v in rec.items() if k != "current_hash"}
                recomputed = hashlib.sha256(canonical_json(body)).hexdigest()
                if not hmac.compare_digest(str(rec.get("current_hash")), recomputed):
                    return False, f"Hash mismatch at line {idx}"
                expected_prev = recomputed
        return True, f"Verified {count} event(s)"
