"""WINDOWS-ONLY integration test. Start MockERP.exe first (dotnet build, then run the exe), then:
    python tests/test_local_uia.py
Exercises: sign -> validate -> claim -> UIA worker subprocess -> ledger read-back -> audit chain."""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))

from security import HashChainAuditLog, ReplayStore, compute_hmac_sha256, validate_execution_job  # noqa: E402
from ws_agent import run_uia_worker  # noqa: E402


def main() -> int:
    device_id, secret = "farhan-demo-pc", "test-secret-key"
    with tempfile.TemporaryDirectory() as tmp:
        store = ReplayStore(Path(tmp) / "jobs.sqlite")
        audit = HashChainAuditLog(Path(tmp) / "audit.jsonl")
        env = {
            "type": "EXECUTE", "job_id": f"FF-T{int(time.time())}", "device_id": device_id,
            "action": "SHORT_PAY", "approval_id": "APR-1001",
            "payload": {"po_number": "PO-1001", "vendor_name": "Eastern Components Pvt Ltd",
                        "invoice_number": "INV-7781", "payable": "47500.00",
                        "status": "SHORT_PAY", "variance": "7500.00"},
            "expires_at": int(time.time()) + 120,
        }
        env["signature"] = compute_hmac_sha256(secret, env)
        job = validate_execution_job(env, expected_device_id=device_id, hmac_secret=secret)
        assert store.claim(job["job_id"], job["device_id"], job["action"])
        result = run_uia_worker(job["payload"])
        store.finish(job["job_id"], result["status"], result)
        audit.append(job_id=job["job_id"], device_id=device_id, action=job["action"],
                     execution_status=result["status"], detail=result.get("detail", ""))
        print("UIA result:", json.dumps(result, indent=2))
        print("Audit chain:", audit.verify_chain())
        return 0 if result["status"] == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
