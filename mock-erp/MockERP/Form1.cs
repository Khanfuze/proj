using System;
using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace MockERP;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new Form1());
    }
}

public partial class Form1 : Form
{
    private readonly TextBox _txtPoNumber = new() { Name = "txtPoNumber", Left = 150, Top = 55, Width = 220 };
    private readonly TextBox _txtVendor = new() { Name = "txtVendor", Left = 150, Top = 95, Width = 220 };
    private readonly TextBox _txtInvoiceNumber = new() { Name = "txtInvoiceNumber", Left = 150, Top = 135, Width = 220 };
    private readonly TextBox _txtPayable = new() { Name = "txtPayable", Left = 150, Top = 175, Width = 220 };
    private readonly TextBox _txtStatus = new() { Name = "txtStatus", Left = 150, Top = 215, Width = 220 };

    private readonly Button _btnSave = new() { Name = "btnSave", Text = "Save to Ledger", Left = 150, Top = 260, Width = 130, Height = 34 };
    private readonly Button _btnClear = new() { Name = "btnClear", Text = "Clear", Left = 290, Top = 260, Width = 80, Height = 34 };

    private readonly DataGridView _gridLedger = new()
    {
        Name = "gridLedger",
        Left = 20,
        Top = 315,
        Width = 760,
        Height = 230,
        ReadOnly = true,
        AllowUserToAddRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
    };

    private readonly Label _lblMessage = new() { Name = "lblMessage", Left = 20, Top = 298, Width = 760, Height = 16, ForeColor = Color.Firebrick };

    public Form1()
    {
        Text = "ForgeFlow MockERP - Procurement Ledger";
        ClientSize = new Size(800, 570);

        var header = new Label
        {
            Text = "ForgeFlow MockERP - Procurement Ledger",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            Left = 20,
            Top = 15,
            AutoSize = true
        };
        Controls.Add(header);

        AddRow("PO Number:", _txtPoNumber, 55);
        AddRow("Vendor Name:", _txtVendor, 95);
        AddRow("Invoice Number:", _txtInvoiceNumber, 135);
        AddRow("Payable Amount:", _txtPayable, 175);
        AddRow("Status:", _txtStatus, 215);

        _gridLedger.Columns.Add("colTimestamp", "Timestamp");
        _gridLedger.Columns.Add("colPoNumber", "PO Number");
        _gridLedger.Columns.Add("colInvoiceNumber", "Invoice Number");
        _gridLedger.Columns.Add("colVendor", "Vendor");
        _gridLedger.Columns.Add("colPayable", "Payable");
        _gridLedger.Columns.Add("colStatus", "Status");

        _btnSave.Click += OnSaveClick;
        _btnClear.Click += (_, _) => ClearInputs();

        Controls.Add(_btnSave);
        Controls.Add(_btnClear);
        Controls.Add(_lblMessage);
        Controls.Add(_gridLedger);

        _txtPoNumber.TabIndex = 0; _txtVendor.TabIndex = 1; _txtInvoiceNumber.TabIndex = 2;
        _txtPayable.TabIndex = 3; _txtStatus.TabIndex = 4; _btnSave.TabIndex = 5; _btnClear.TabIndex = 6;
    }

    private void AddRow(string labelText, Control input, int top)
    {
        var lbl = new Label
        {
            Text = labelText,
            Left = 20,
            Top = top + 4,
            Width = 120
        };
        Controls.Add(lbl);
        input.Top = top;
        Controls.Add(input);
    }

    private void OnSaveClick(object? sender, EventArgs e)
    {
        // Validate in-form (a MessageBox would block UI Automation). Invalid input is never written to the ledger.
        string po = _txtPoNumber.Text.Trim(), vendor = _txtVendor.Text.Trim(), inv = _txtInvoiceNumber.Text.Trim();
        string payable = _txtPayable.Text.Trim(), status = _txtStatus.Text.Trim();
        if (po.Length == 0 || vendor.Length == 0 || inv.Length == 0 || status.Length == 0)
        {
            _lblMessage.Text = "All fields are required.";
            return;
        }
        if (!decimal.TryParse(payable, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amt) || amt < 0)
        {
            _lblMessage.Text = "Payable must be a non-negative number (e.g. 47500.00).";
            return;
        }
        _lblMessage.Text = string.Empty;

        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        _gridLedger.Rows.Add(
            timestamp,
            po, inv, vendor, payable, status
        );
        ClearInputs();
    }

    private void ClearInputs()
    {
        _txtPoNumber.Clear();
        _txtVendor.Clear();
        _txtInvoiceNumber.Clear();
        _txtPayable.Clear();
        _txtStatus.Clear();
        _lblMessage.Text = string.Empty;
    }
}
