"""Platform-independent tests (no Windows / pywinauto needed). Run: python -m unittest discover tests -v"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))

from security import (HashChainAuditLog, ReplayStore, SecurityValidationError,  # noqa: E402
                      compute_hmac_sha256, validate_execution_job)
import ws_agent  # noqa: E402

DEV, SECRET = "farhan-demo-pc", "test-secret-key"


def make_env(**over):
    env = {
        "type": "EXECUTE", "job_id": "FF-000001", "device_id": DEV, "action": "SHORT_PAY",
        "approval_id": "APR-1001",
        "payload": {"po_number": "PO-1001", "vendor_name": "Eastern Components Pvt Ltd",
                    "invoice_number": "INV-7781", "payable": "47500.00", "status": "SHORT_PAY",
                    "variance": "7500.00"},
        "expires_at": int(time.time()) + 120,
    }
    env.update(over)
    env["signature"] = compute_hmac_sha256(SECRET, env)
    return env


def good_exec(payload):
    return {"status": "SUCCESS", "detail": "ERP save verified", "pid": 1,
            "ledger_entry": {**payload, "verified": True}}


class Validation(unittest.TestCase):
    def v(self, env, **kw):
        return validate_execution_job(env, expected_device_id=DEV, hmac_secret=SECRET, **kw)

    def test_valid(self):
        self.assertEqual(self.v(make_env())["payload"]["payable"], "47500.00")

    def test_tampered_payload(self):
        e = make_env(); e["payload"]["payable"] = "1.00"
        with self.assertRaisesRegex(SecurityValidationError, "signature"):
            self.v(e)

    def test_wrong_secret(self):
        with self.assertRaises(SecurityValidationError):
            validate_execution_job(make_env(), expected_device_id=DEV, hmac_secret="other")

    def test_expired(self):
        with self.assertRaisesRegex(SecurityValidationError, "expired"):
            self.v(make_env(expires_at=int(time.time()) - 5))

    def test_ttl_too_long(self):
        with self.assertRaisesRegex(SecurityValidationError, "lifetime"):
            self.v(make_env(expires_at=int(time.time()) + 100000))

    def test_wrong_device(self):
        with self.assertRaisesRegex(SecurityValidationError, "Device"):
            self.v(make_env(device_id="evil-pc"))

    def test_disallowed_action(self):
        with self.assertRaisesRegex(SecurityValidationError, "Disallowed"):
            self.v(make_env(action="RUN_SHELL"))

    def test_status_must_match_action(self):
        e = make_env(); e["payload"]["status"] = "APPROVE"; e["signature"] = compute_hmac_sha256(SECRET, {k: v for k, v in e.items() if k != "signature"})
        with self.assertRaisesRegex(SecurityValidationError, "status"):
            self.v(e)

    def test_extra_payload_key_rejected(self):
        e = make_env(); e["payload"]["exe_path"] = "C:/x.exe"
        e["signature"] = compute_hmac_sha256(SECRET, {k: v for k, v in e.items() if k != "signature"})
        with self.assertRaisesRegex(SecurityValidationError, "unexpected"):
            self.v(e)

    def test_extra_envelope_key_rejected(self):
        e = make_env(cmd="calc.exe")
        with self.assertRaisesRegex(SecurityValidationError, "unexpected"):
            self.v(e)

    def test_bad_money(self):
        for bad in ("1e3", "NaN", "-5", "47500.001", "abc", ""):
            e = make_env(); e["payload"]["payable"] = bad
            e["signature"] = compute_hmac_sha256(SECRET, {k: v for k, v in e.items() if k != "signature"})
            with self.assertRaises(SecurityValidationError, msg=bad):
                self.v(e)

    def test_non_string_money_rejected(self):
        e = make_env(); e["payload"]["payable"] = 47500.0
        e["signature"] = compute_hmac_sha256(SECRET, {k: v for k, v in e.items() if k != "signature"})
        with self.assertRaises(SecurityValidationError):
            self.v(e)

    def test_bool_expiry_rejected(self):
        with self.assertRaises(SecurityValidationError):
            self.v(make_env(expires_at=True))


class ReplayAndAudit(unittest.TestCase):
    def test_claim_atomic_and_finish_persists(self):
        with tempfile.TemporaryDirectory() as t:
            s = ReplayStore(Path(t) / "j.sqlite")
            self.assertTrue(s.claim("J1", DEV, "SHORT_PAY"))
            self.assertFalse(s.claim("J1", DEV, "SHORT_PAY"))
            s.finish("J1", "SUCCESS", {"status": "SUCCESS"})          # old INSERT-OR-IGNORE bug: this was dropped
            s2 = ReplayStore(Path(t) / "j.sqlite")                   # "restart"
            self.assertEqual(s2.get("J1")["status"], "SUCCESS")
            self.assertFalse(s2.claim("J1", DEV, "SHORT_PAY"))

    def test_chain_detects_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            log = HashChainAuditLog(Path(t) / "a.jsonl")
            for i in range(3):
                log.append(job_id=f"J{i}", device_id=DEV, action="APPROVE", execution_status="SUCCESS")
            self.assertTrue(log.verify_chain()[0])
            p = Path(t) / "a.jsonl"
            p.write_text(p.read_text().replace("J1", "JX", 1))
            self.assertFalse(log.verify_chain()[0])

    def test_corrupt_tail_refuses_to_extend(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.jsonl"
            log = HashChainAuditLog(p)
            log.append(job_id="J", device_id=DEV, action="A", execution_status="S")
            p.write_text(p.read_text() + "{garbage\n")
            with self.assertRaises(RuntimeError):
                log.append(job_id="J2", device_id=DEV, action="A", execution_status="S")


class AgentFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.cfg = {"device_id": DEV, "hmac_secret": SECRET}
        self.store, self.log = ReplayStore(t / "j.sqlite"), HashChainAuditLog(t / "a.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def run_msg(self, raw, executor=good_exec):
        return asyncio.run(ws_agent.process_incoming_message(
            raw, cfg=self.cfg, replay_store=self.store, audit_log=self.log, executor=executor))

    def test_success_then_replay_redelivers_without_reexecuting(self):
        calls = []
        def ex(p): calls.append(p); return good_exec(p)
        raw = json.dumps(make_env())
        r1 = self.run_msg(raw, ex)
        r2 = self.run_msg(raw, ex)
        self.assertEqual(r1["status"], "SUCCESS")
        self.assertEqual(r2["status"], "SUCCESS"); self.assertTrue(r2["replayed"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(self.log.verify_chain()[0])

    def test_control_messages_never_answered_as_jobs(self):
        self.assertIsNone(self.run_msg(json.dumps({"type": "REGISTER_ACK"})))
        self.assertIsNone(self.run_msg(json.dumps({"type": "ERROR", "detail": "bad token"})))
        self.assertEqual(self.run_msg(json.dumps({"type": "PING"})), {"type": "PONG"})

    def test_non_object_and_garbage(self):
        self.assertIsNone(self.run_msg("[1,2,3]"))
        self.assertIsNone(self.run_msg("not json"))
        self.assertIsNone(self.run_msg(b"\xff\xfe"))

    def test_executor_crash_gives_failed_not_hang(self):
        def boom(p): raise RuntimeError("ElementNotFoundError")
        r = self.run_msg(json.dumps(make_env()), boom)
        self.assertEqual(r["status"], "FAILED")
        self.assertEqual(self.store.get("FF-000001")["status"], "FAILED")

    def test_success_without_verified_ledger_is_downgraded(self):
        r = self.run_msg(json.dumps(make_env()), lambda p: {"status": "SUCCESS", "detail": "x", "ledger_entry": None})
        self.assertEqual(r["status"], "FAILED")

    def test_rejected_job_not_claimed(self):
        e = make_env(); e["payload"]["payable"] = "1.00"
        self.assertEqual(self.run_msg(json.dumps(e))["status"], "REJECTED")
        self.assertFalse(self.store.has_seen("FF-000001"))


class WorkerProtocol(unittest.TestCase):
    def _worker(self, body):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        p = Path(d.name) / "w.py"; p.write_text(textwrap.dedent(body)); return p

    def test_good_worker(self):
        w = self._worker('''
            import json,sys
            print("pywinauto noise")
            print("FORGEFLOW_RESULT:" + json.dumps({"status":"SUCCESS","detail":"ok","ledger_entry":{"verified":True}}))''')
        self.assertEqual(ws_agent.run_uia_worker({}, worker_path=w)["status"], "SUCCESS")

    def test_crashing_worker(self):
        w = self._worker("raise SystemExit(3)")
        self.assertEqual(ws_agent.run_uia_worker({}, worker_path=w)["status"], "FAILED")

    def test_timeout(self):
        w = self._worker("import time; time.sleep(5)")
        self.assertIn("timed out", ws_agent.run_uia_worker({}, worker_path=w, timeout=1)["detail"])

    def test_unverified_success_rejected(self):
        w = self._worker('import json;print("FORGEFLOW_RESULT:"+json.dumps({"status":"SUCCESS","detail":"x"}))')
        self.assertEqual(ws_agent.run_uia_worker({}, worker_path=w)["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
