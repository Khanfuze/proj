from __future__ import annotations

import asyncio
import json
import os
import random
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import websockets  # noqa: E402

from security import (  # noqa: E402
    HashChainAuditLog,
    ReplayStore,
    SecurityValidationError,
    validate_execution_job,
)
from uia_worker import RESULT_PREFIX  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("FORGEFLOW_DATA_DIR") or BASE_DIR / "data")
WORKER_PATH = Path(__file__).resolve().parent / "uia_worker.py"  # fixed; never cloud-supplied
WORKER_TIMEOUT_S = 60
MAX_MSG_BYTES = 64 * 1024
WEAK = {"", "dev-token-change-me", "dev-hmac-secret-change-me"}


def load_config() -> dict[str, str]:
    cfg = {
        "ws_url": os.environ.get("FORGEFLOW_WS_URL", "ws://127.0.0.1:8000/ws/agent").strip(),
        "device_id": os.environ.get("FORGEFLOW_DEVICE_ID", "farhan-demo-pc").strip(),
        "device_token": os.environ.get("FORGEFLOW_DEVICE_TOKEN", "").strip(),
        "hmac_secret": os.environ.get("FORGEFLOW_HMAC_SECRET", "").strip(),
    }
    if cfg["device_token"] in WEAK or cfg["hmac_secret"] in WEAK:
        raise SystemExit("Set FORGEFLOW_DEVICE_TOKEN and FORGEFLOW_HMAC_SECRET (non-default) before starting.")
    u = urlparse(cfg["ws_url"])
    if u.scheme not in ("ws", "wss"):
        raise SystemExit("FORGEFLOW_WS_URL must be ws:// or wss://")
    if u.scheme == "ws" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Plain ws:// is only allowed for localhost; use wss:// for any remote cloud.")
    return cfg


def run_uia_worker(payload: dict[str, Any], worker_path: Path = WORKER_PATH,
                   timeout: int = WORKER_TIMEOUT_S) -> dict[str, Any]:
    """Run the fixed UIA worker script in a separate process; fail closed on anything odd."""
    try:
        proc = subprocess.run(
            [sys.executable, str(worker_path)],
            input=json.dumps(payload) + "\n",
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "FAILED", "detail": f"UIA worker timed out after {timeout}s; ERP state unknown, check ledger manually"}
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                res = json.loads(line[len(RESULT_PREFIX):])
            except json.JSONDecodeError:
                break
            if isinstance(res, dict) and res.get("status") in ("SUCCESS", "FAILED"):
                if res["status"] == "SUCCESS" and not (res.get("ledger_entry") or {}).get("verified") is True:
                    return {"status": "FAILED", "detail": "Worker claimed SUCCESS without verified ledger entry"}
                return res
    tail = (proc.stderr or "").strip().splitlines()[-1:] or [""]
    return {"status": "FAILED", "detail": f"UIA worker produced no valid result (rc={proc.returncode}) {tail[0]}"[:300]}


def _result(job_id: str, status: str, detail: str, ledger: dict | None = None, **extra: Any) -> dict[str, Any]:
    return {"type": "RESULT", "job_id": job_id, "status": status, "detail": detail, "ledger_entry": ledger, **extra}


async def process_incoming_message(
    raw_msg: str | bytes,
    *,
    cfg: dict[str, str],
    replay_store: ReplayStore,
    audit_log: HashChainAuditLog,
    executor: Callable[[dict[str, Any]], dict[str, Any]] = run_uia_worker,
) -> dict[str, Any] | None:
    dev = cfg["device_id"]
    try:
        envelope = json.loads(raw_msg)
    except (json.JSONDecodeError, UnicodeDecodeError):
        audit_log.append(job_id="UNKNOWN", device_id=dev, action="PARSE_ERROR",
                         execution_status="REJECTED", detail="Malformed JSON")
        return None
    if not isinstance(envelope, dict):
        audit_log.append(job_id="UNKNOWN", device_id=dev, action="PARSE_ERROR",
                         execution_status="REJECTED", detail="Envelope is not an object")
        return None

    mtype = envelope.get("type")
    if mtype == "PING":
        return {"type": "PONG"}
    if mtype != "EXECUTE":
        print(f"[Agent] control message: {str(mtype)[:32]}")  # REGISTER_ACK / ERROR etc: never answered as a job
        return None

    job_id = str(envelope.get("job_id") or "UNKNOWN")[:64]
    action = str(envelope.get("action") or "UNKNOWN")[:32]

    try:
        job = validate_execution_job(envelope, expected_device_id=dev, hmac_secret=cfg["hmac_secret"])
    except SecurityValidationError as exc:
        audit_log.append(job_id=job_id, device_id=dev, action=action, execution_status="REJECTED", detail=str(exc))
        return _result(job_id, "REJECTED", str(exc))

    jid = job["job_id"]
    if not replay_store.claim(jid, dev, job["action"]):
        prior = replay_store.get(jid) or {}
        audit_log.append(job_id=jid, device_id=dev, action=job["action"], execution_status="DUPLICATE",
                         detail=f"Replay blocked (prior status {prior.get('status')})")
        if prior.get("result"):
            return {**prior["result"], "replayed": True}  # re-deliver original outcome; never re-execute
        return _result(jid, "FAILED" if prior.get("status") != "IN_PROGRESS" else "IN_PROGRESS",
                       "Duplicate job; original execution did not record a result", replayed=True)

    audit_log.append(job_id=jid, device_id=dev, action=job["action"], execution_status="ACCEPTED",
                     detail="Signature, expiry, allowlist, schema, replay checks passed")

    try:
        res = await asyncio.to_thread(executor, job["payload"])  # waiting on a subprocess; thread is fine
    except BaseException as exc:  # noqa: BLE001
        res = {"status": "FAILED", "detail": f"Executor error: {type(exc).__name__}: {exc}"}

    ok = res.get("status") == "SUCCESS" and (res.get("ledger_entry") or {}).get("verified") is True
    status = "SUCCESS" if ok else "FAILED"
    detail = res.get("detail", "") if ok else (res.get("detail") or "Execution failed")
    out = _result(jid, status, detail, res.get("ledger_entry") if ok else None)
    replay_store.finish(jid, status, out)
    audit_log.append(job_id=jid, device_id=dev, action=job["action"], execution_status=status, detail=detail,
                     extra={"pid": res.get("pid"), "ledger_entry": out["ledger_entry"]})
    return out


async def run_agent_loop() -> None:
    cfg = load_config()
    replay_store = ReplayStore(DATA_DIR / "processed_jobs.sqlite")
    audit_log = HashChainAuditLog(DATA_DIR / "audit.jsonl")
    ok, msg = audit_log.verify_chain()
    print(f"[Agent] Audit chain: {msg}")
    if not ok:
        raise SystemExit("Local audit log failed verification; refusing to start.")

    backoff = 1.0
    while True:
        try:
            print(f"[Agent] Connecting outbound to {cfg['ws_url']} as '{cfg['device_id']}'...")
            async with websockets.connect(cfg["ws_url"], ping_interval=20, ping_timeout=20,
                                          max_size=MAX_MSG_BYTES) as ws:
                await ws.send(json.dumps({
                    "type": "REGISTER", "device_id": cfg["device_id"],
                    "auth_token": cfg["device_token"], "capabilities": ["UIA_MOCK_ERP"],
                }))
                print("[Agent] Registered. Waiting for signed execution jobs...")
                backoff = 1.0
                async for raw in ws:
                    reply = await process_incoming_message(raw, cfg=cfg, replay_store=replay_store, audit_log=audit_log)
                    if reply is not None:
                        await ws.send(json.dumps(reply))
        except (OSError, websockets.exceptions.WebSocketException) as exc:
            print(f"[Agent] Connection error: {exc}")
        except Exception:  # noqa: BLE001 - keep agent alive but never hide the bug
            traceback.print_exc()
        delay = backoff + random.uniform(0, 0.5)
        print(f"[Agent] Reconnecting in {delay:.1f}s...")
        await asyncio.sleep(delay)
        backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    try:
        asyncio.run(run_agent_loop())
    except KeyboardInterrupt:
        pass
