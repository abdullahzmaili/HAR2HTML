# Instructions

## Requirements

- Windows PowerShell 5.1 or later (PowerShell 7+ required for Brotli decoding).
- A modern browser (Edge, Chrome or Firefox).
- A `.har` file. Only one file is accepted per run.

## Run

```powershell
.\Convert-HarToHtml.ps1 -HarPath <file.har> [-OutPut <folder>] [-Open] [-RedactSecrets]
```

If script execution is blocked, run once: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-HarPath` | Path to the HAR file. Required. |
| `-OutputPath` (`-OutPut`) | Folder for the report. Default: the HAR file's folder. |
| `-OpenReport` (`-Open`) | Opens the report when finished. |
| `-RedactSecrets` | Masks authorization headers, cookies, tokens, passwords and SAML assertions. |

## Output

`<HarName>_Report_<yyyyMMdd_HHmmss>.html` in the output folder. The file is self-contained and works offline.

Exit codes: `0` success, `1` HAR file not found, `2` conversion failed.

## Using the Report

| Area | Use |
|------|-----|
| Sessions grid | One row per request. Click a row to inspect it. Use the column filters to narrow the list. |
| Request / Response tabs | Headers, body views (text, JSON, XML, forms, hex, preview), cookies, auth and SAML decoding, raw and timing. |
| Search | Searches URLs, headers and bodies. Matching rows are highlighted. |
| Insights | Detected problems such as HTTP errors, AADSTS codes, CORS, expired JWTs and slow responses. |
| Timeline | Waterfall view of request timing. |
| Export | Save selected sessions as CSV, text or HAR, or copy as cURL/PowerShell. |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "HAR file not found" | Check the path and quote it if it contains spaces. |
| "No request body" | Normal for GET, HEAD, DELETE and 204/304 responses. |
| "Body not captured by the browser" | The browser did not save the body. Re-capture with **Save all as HAR with content**. |
| Large HAR is slow | Processing a 30 MB file takes about 10-15 seconds. Bodies over 5 MB are truncated. |

## Security

HAR files and reports can contain tokens, cookies and personal data. Use `-RedactSecrets` and share only through approved channels.
