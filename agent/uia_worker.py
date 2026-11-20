from __future__ import annotations

import os
import time
from typing import Any

import psutil
from pywinauto import Desktop


WINDOW_TITLE_SUBSTRING = "ForgeFlow MockERP"
EXPECTED_EXE_NAME = "mockerp.exe"

FIELD_TO_AUTOMATION_ID = {
    "po_number": "txtPoNumber",
    "vendor": "txtVendor",
    "invoice_number": "txtInvoiceNumber",
    "payable": "txtPayable",
    "status": "txtStatus",
}


class UiaExecutionError(Exception):
    """Raised when process verification, UIA interaction, or read-back fails."""


def _find_verified_erp_window(timeout: float = 8.0):
    expected_exe = os.environ.get("MOCK_ERP_EXE_NAME", EXPECTED_EXE_NAME).strip().lower()
    deadline = time.monotonic() + timeout

    desktop = Desktop(backend="uia")
    while time.monotonic() < deadline:
        windows = desktop.windows(visible_only=True)
        for win in windows:
            try:
                title = win.window_text() or ""
                if WINDOW_TITLE_SUBSTRING.lower() not in title.lower():
                    continue
                pid = win.process_id()
                if not pid:
                    continue
                proc_name = psutil.Process(pid).name().lower()
                if proc_name != expected_exe:
                    continue
                hwnd = int(win.handle)
                win_spec = desktop.window(handle=hwnd)
                return win_spec, pid, hwnd, proc_name
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue
        time.sleep(0.25)

    raise UiaExecutionError(
        f"Could not find visible window matching '{WINDOW_TITLE_SUBSTRING}' owned by '{expected_exe}'"
    )


def _set_edit_and_verify(win, automation_id: str, expected_value: str) -> str:
    ctrl = win.child_window(auto_id=automation_id, control_type="Edit")
    ctrl.wait("visible enabled", timeout=5)

    try:
        ctrl.draw_outline(colour="green", thickness=2)
    except Exception:
        pass

    try:
        ctrl.set_edit_text(expected_value)
    except Exception:
        ctrl.click_input()
        ctrl.type_keys("^a{BACKSPACE}", set_foreground=False)
        ctrl.type_keys(expected_value, with_spaces=True, set_foreground=False)

    time.sleep(0.1)

    actual_value = ""
    try:
        val = ctrl.get_value()
        actual_value = "" if val is None else str(val)
    except Exception:
        actual_value = (ctrl.window_text() or "").strip()

    if actual_value.strip() != expected_value.strip():
        raise UiaExecutionError(
            f"Read-back mismatch on {automation_id}: expected '{expected_value}', got '{actual_value}'"
        )

    return actual_value


def _cell_text(elem) -> str:
    try:
        val = elem.get_value()
        if val is not None and str(val).strip():
            return str(val).strip()
    except Exception:
        pass
    try:
        txt = elem.window_text()
        if txt is not None:
            return str(txt).strip()
    except Exception:
        pass
    return ""


def _read_ledger_rows(win) -> list[list[str]]:
    # WinForms DataGridView exposes auto_id="gridLedger" (often as DataGrid rather than Table)
    grid = win.child_window(auto_id="gridLedger")
    grid.wait("visible", timeout=5)
    grid_wrapper = grid.wrapper_object()

    rows: list[list[str]] = []
    data_items = list(grid_wrapper.children(control_type="DataItem"))
    if not data_items:
        for child in grid_wrapper.children():
            try:
                data_items.extend(child.children(control_type="DataItem"))
            except Exception:
                continue

    for item in data_items:
        cells = [_cell_text(cell) for cell in item.children()]
        if any(cells):
            rows.append(cells)

    return rows


def execute_erp_entry(payload: dict[str, Any]) -> dict[str, Any]:
    """Populate MockERP fields via UIA, invoke Save, and verify saved row in ledger."""
    win, pid, hwnd, exe_name = _find_verified_erp_window()

    try:
        win.set_focus()
    except Exception:
        pass

    po_number = str(payload["po_number"]).strip()
    vendor_name = str(payload["vendor_name"]).strip()
    invoice_number = str(payload["invoice_number"]).strip()
    payable = str(payload["payable"]).strip()
    status = str(payload["status"]).strip()

    values_to_write = {
        "po_number": po_number,
        "vendor": vendor_name,
        "invoice_number": invoice_number,
        "payable": payable,
        "status": status,
    }

    verified_fields: dict[str, str] = {}
    for key, auto_id in FIELD_TO_AUTOMATION_ID.items():
        verified_fields[key] = _set_edit_and_verify(win, auto_id, values_to_write[key])

    save_btn = win.child_window(auto_id="btnSave", control_type="Button")
    save_btn.wait("visible enabled", timeout=5)
    try:
        save_btn.draw_outline(colour="blue", thickness=2)
    except Exception:
        pass

    try:
        save_btn.invoke()
    except Exception:
        save_btn.click_input()

    time.sleep(0.25)

    rows = _read_ledger_rows(win)
    matched_row = None
    for row in reversed(rows):
        # Expected columns: [Timestamp, PO Number, Invoice Number, Vendor, Payable, Status]
        if len(row) >= 6:
            _, r_po, r_inv, r_vendor, r_payable, r_status = row[:6]
            if (
                r_po == po_number
                and r_inv == invoice_number
                and r_vendor == vendor_name
                and r_payable == payable
                and r_status == status
            ):
                matched_row = row[:6]
                break

    if matched_row is None:
        raise UiaExecutionError(
            f"Post-save ledger verification failed for PO={po_number}, Invoice={invoice_number}"
        )

    return {
        "status": "SUCCESS",
        "detail": "ERP save verified",
        "pid": pid,
        "hwnd": hex(hwnd),
        "exe": exe_name,
        "verified_fields": verified_fields,
        "ledger_entry": {
            "timestamp": matched_row[0],
            "po_number": matched_row[1],
            "invoice_number": matched_row[2],
            "vendor_name": matched_row[3],
            "payable": matched_row[4],
            "status": matched_row[5],
            "verified": True,
        },
    }