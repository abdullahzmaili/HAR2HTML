# Quick Start

## 1. Capture a HAR file

In Edge or Chrome: open **DevTools (F12)** > **Network** > enable **Preserve log** > reproduce the issue > right-click the list > **Save all as HAR with content**.

## 2. Generate the report

```powershell
.\Convert-HarToHtml.ps1 -HarPath "C:\temp\trace.har" -OutPut "C:\temp\Reports" -Open
```

If `-OutPut` is omitted, the report is saved next to the HAR file. `-Open` opens it in the default browser.

## 3. Review the report

1. Select a row in the sessions grid to inspect its request and response.
2. Use the search box to find a URL, header or body value.
3. Filter by status, method or type to isolate failures (4xx/5xx).
4. Check the **Insights** for detected problems (AADSTS codes, CORS, expired JWTs, slow responses).

## 4. Share safely

Add `-RedactSecrets` to mask tokens, cookies and credentials before sharing the report.
