# Quick Start

## 1. Capture a HAR file

In Edge or Chrome: open **DevTools (F12)** > **Network** > enable **Preserve log** > reproduce the issue > right-click the list > **Save all as HAR with content**.

## 2. Generate the report

```powershell
.\HAR2HTML.ps1 -HarPath "C:\temp\trace.har" -OutputPath "C:\temp\Reports" -Open
```

If `-OutputPath` is omitted, the report is saved next to the HAR file. `-Open` opens it in the default browser. Only `.har` files are supported.

## 3. Review the report

1. Select a row in the sessions grid to inspect its request and response.
2. Use the search box to find a URL, header or body value, or the find box above a Request or Response pane to search the open tab.
3. Filter by status, method or type to isolate failures (4xx/5xx).
4. Check the **Insights** for detected problems (AADSTS codes, CORS, expired JWTs, slow responses).
5. For support cases, add the **Correlation ID** and **x-ms-request-id** columns from **Columns**.

## 4. Share safely

A report made without `-RedactSecrets` contains tokens, cookies and credentials unmasked. Use `-RedactSecrets` before sharing: secrets are masked when the report is generated and cannot be revealed afterwards.
