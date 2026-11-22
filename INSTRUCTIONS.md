# Instructions

## Requirements

- Windows PowerShell 5.1 or later (PowerShell 7+ required for Brotli decoding).
- A modern browser (Edge, Chrome or Firefox).
- A `.har` file. Only one file is accepted per run.

## Run

```powershell
.\HAR2HTML.ps1 -HarPath <file.har> [-OutputPath <folder or file>] [-Open] [-RedactSecrets]
```

If script execution is blocked, run once: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-HarPath` | Path to the HAR file. Required. Only `.har` files are supported. |
| `-OutputPath` (`-OutPut`) | Folder or file for the report. Default: the HAR file's folder. A file path without `.htm` or `.html` gets `.html` appended. Missing folders are created. |
| `-Open` | Opens the report when finished. |
| `-RedactSecrets` | Permanently masks secrets while the report is generated (see Security). Without it, nothing is masked. |

## Output

`<HarName>_Report_<yyyyMMdd_HHmmss>.html` in the output folder (or the exact file name if `-OutputPath` is a file). The file is self-contained and works offline.

Exit codes: `0` success, `1` invalid input (file missing, empty, ZIP-based archive, not a HAR, or unsupported HAR version), `2` parse or conversion failure (for example invalid JSON). Errors are printed as `ERROR: ...`.

## Using the Report

| Area | Use |
|------|-----|
| Left tabs | **Sessions**, **Summary**, **Timeline**, **Insights**, **Capture info**. |
| Sessions grid | One row per request. Click a row to inspect it. Use the column filters to narrow the list. **Correlation ID** and **x-ms-request-id** are hidden by default; enable them in **Columns**. |
| Request / Response tabs | Headers, body views (TextView, JSON, XML, WebForms, hex, preview), cookies, auth and SAML decoding, raw, timing, redirects, caching, WebSocket and per-session insights. |
| Search | The top search box searches URLs, headers and bodies, with case, regex, whole-word and scope options. Matching rows are highlighted. |
| Find in pane | The box above each Request and Response pane searches the open tab and highlights matches in yellow. Enter = next, Shift+Enter = previous, Esc = clear. |
| Insights | Detected problems such as HTTP errors, AADSTS codes, CORS, expired JWTs and slow responses. |
| Timeline | Waterfall view of request timing. |
| Export | **Export** menu: the filtered list as CSV, the selected session as text, or the filtered sessions as HAR. |
| Right-click menu | Copy as cURL (bash), Copy as cURL (PowerShell), Copy as PowerShell. Paste cURL into the matching shell. |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Input file not found" | Check the path and quote it if it contains spaces. |
| "Unsupported file ... is a ZIP-based archive" | Only browser `.har` files are accepted. |
| "The HAR file is truncated or corrupted ... Recovered N complete entries" | The file was cut off while saving. The report contains only the complete entries. Re-export the HAR for the full trace. |
| "The file is not valid JSON" | The file is corrupted or is not a HAR. Re-export it. |
| "No request body" / "No response body" | Normal for requests without a payload (most GET, HEAD, DELETE) and for 1xx, 204, 3xx responses and HEAD requests. |
| "Body not captured by the browser" | The browser did not save the body. Re-capture with **Save all as HAR with content**. |
| Large HAR is slow | Processing a 30 MB file takes roughly 15-30 seconds, depending on the content and PowerShell version. Text bodies over 5 MB are truncated; larger binary bodies are not embedded. |
| Brotli body shown as binary | Brotli decoding needs PowerShell 7+. |

## Security

HAR files and reports can contain tokens, cookies and personal data.

- **Default (no `-RedactSecrets`):** the report contains all values unmasked, including passwords, tokens, cookies and secrets. Treat it as sensitive.
- **With `-RedactSecrets`:** secrets are masked while the report is generated (short values and all passwords and secrets are fully masked; longer values keep at most 4 characters at each end, for example `eyJ0****Xk2Q`). The original values are never written to the file and cannot be revealed afterwards. Masking is name-based, so review a redacted report before sharing it. Insight texts, error text and page titles are masked too, and decoded JWT claims and SAML XML are withheld.

Use `-RedactSecrets` before sharing a report, and share only through approved channels.
