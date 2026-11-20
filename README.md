**ForgeFlow AI** is built around four layers—two in the cloud/browser and two running locally on your Windows machine—connected so that AI helps extract messy documents, deterministic code handles financial truth and security gates, a human authorizes the decision, and Windows UI Automation executes the verified entry in `MockERP.exe`.

---

### 1. The Four-Layer Architecture

#### Layer 1 — Public Website (React + TypeScript + Vite on Vercel)

* **Who owns it:** Your friend.
* **What it does:** Gives the user the UI to upload `PO.pdf`, `GRN.pdf`, and `Invoice.pdf`, view extracted fields and reconciliation mismatches, click **Approve**, **Short-Pay + Issue Debit Note**, or **Put On Hold**, and inspect execution results, Debit Notes, and audit logs.
* **Trust boundary:** The browser **never** talks directly to your Windows PC or `MockERP.exe`; every action goes through the cloud backend.

#### Layer 2 — Cloud Backend (Python + FastAPI)

* **Who owns it:** Your friend (with shared API contracts and security/execution coordination).
* **What it does:** Receives uploaded PDFs, runs OCR/LLM extraction into structured JSON, runs deterministic three-way matching (`Decimal` math for ordered vs. received vs. invoiced quantities and prices), creates a signed execution job after human approval, tracks job state/audit records, and generates Vendor Debit Notes.

#### Layer 3 — Secure Execution Gateway (Outbound WebSocket + HMAC-SHA256)

* **Who owns it:** You on the Windows client side (paired with the cloud's server-side WebSocket gateway).
* **Why outbound WebSocket?** Your Windows laptop may sit behind NAT, a router, or a firewall, so you **never** open an inbound port on your PC. Instead, your Windows Desktop Agent initiates an outbound WebSocket (`ws://` / `wss://`) connection to the cloud and receives signed execution jobs over that active channel.
* **Security controls:** Verifies device identity, `expires_at` lifetime, allowed actions (`APPROVE`, `SHORT_PAY`, `HOLD`), payload schema/amounts, HMAC-SHA256 signature over canonical JSON, and SQLite-backed replay/idempotency (`job_id`) before touching anything local.

#### Layer 4 — Local Windows Execution (`ws_agent.py` → `uia_worker.py` → `MockERP.exe`)

* **Who owns it:** You.
* **How the pieces split locally:**
1. **`ws_agent.py` (Outbound Agent):** Maintains the outbound WebSocket connection (with reconnect backoff), validates incoming `EXECUTE` envelopes via `security.py`, records job status in SQLite, appends tamper-evident SHA-256 hash-chained events to `audit.jsonl`, and reports `RESULT` back to the cloud.
2. **`uia_worker.py` (`pywinauto` UIA Worker):** Finds the top-level window matching `ForgeFlow MockERP`, verifies its `PID` belongs to `mockerp.exe`, locates controls by UIA `AutomationId` (`txtPoNumber`, `txtVendor`, `txtInvoiceNumber`, `txtPayable`, `txtStatus`, `btnSave`, `gridLedger`), writes values and reads them back to verify, invokes `Save`, and reads the ledger grid back to confirm the row was actually saved.
3. **`MockERP.exe` (C# .NET 8 WinForms):** The native Windows desktop application (`HWND` / UIA control tree) displaying the form inputs and live ledger `DataGridView` in your interactive desktop session.



---

### 2. End-to-End Flow at a Glance

```text
[Browser: React UI]
       │  HTTPS (Upload PDFs, Review Discrepancy, Click Approve / Short-Pay)
       ▼
[Cloud: FastAPI Backend]
       │  1. AI extracts PO / GRN / Invoice JSON
       │  2. Deterministic Python calculates expected payable & variance
       │  3. Human approves -> creates signed EXECUTE envelope (HMAC-SHA256)
       │
       │  Outbound WebSocket (initiated by Windows PC; no inbound PC port)
       ▼
[Windows: ws_agent.py + security.py]
       │  Checks device_id, expiry, action allowlist, HMAC, SQLite job_id
       │  Appends hash-chained entry to audit.jsonl
       ▼
[Windows: uia_worker.py (pywinauto UIA)]
       │  Checks PID -> mockerp.exe, gets HWND, sets fields via AutomationId,
       │  verifies read-back, invokes btnSave, reads gridLedger to confirm save
       ▼
[Windows: MockERP.exe (C# WinForms)]
       │  New row appears in ledger; result flows back Agent -> Cloud -> UI

```

---

### 3. Key Guardrails Built Into This Architecture

* **AI proposes, deterministic code disposes:** LLMs extract messy text; deterministic `Decimal` logic computes money/discrepancies, and humans authorize before execution.
* **No blind coordinates or unverified saves:** UIA uses `AutomationId`s and checks `gridLedger` after saving—if verification fails, it returns `FAILED`, never a fake `SUCCESS`.
* **Interactive session required:** UIA needs a live interactive Windows desktop session (not a headless Windows service).

Does the full picture from React/Cloud down to `PID` verification and `MockERP.exe` click together cleanly now?
