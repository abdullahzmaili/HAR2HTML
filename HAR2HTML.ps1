<#
.SYNOPSIS
HAR2HTML - converts a browser HAR trace into an interactive HTML report.

.DESCRIPTION
This script reads a browser HAR trace (Edge, Chrome, Firefox or other HAR export), normalizes every entry, decodes request and
response bodies (base64, gzip/deflate/brotli, URL-encoding, forms, multipart, JSON, XML, JWT, SAML, cookies,
binary, WebSocket frames), detects common problems (AADSTS codes, CORS, expired JWTs, slow TTFB, ...) and
embeds everything as JSON in a single HTML file. The report uses a classic HTTP debugging proxy layout
(sessions grid, request/response inspectors, search, filters, timeline, insights) so engineers can troubleshoot
web, authentication and API issues offline. No network calls are made; the only output is the report.

.NOTES
File Name      : HAR2HTML.ps1
Author         : Abdullah Zmaili
Version        : 1.0
Date Created   : 2026-October-27
Date Updated   : 2026-October-27
Prerequisite   : Windows PowerShell 5.1 or later (PowerShell 7+ supported). No external modules required.
                 Brotli decompression is available on PowerShell 7+ only.

DISCLAIMER
This script has been tested across various scenarios. However, by using it, you acknowledge and agree that:
1. You are responsible for how you use the script and any outcomes resulting from its execution.
2. The entire risk arising out of the use or performance of the script remains with you.
3. The author and contributors are not liable for any damages, including data loss, business interruption,
   or other losses, even if warned of the risks.

SECURITY NOTES:
- HAR content is untrusted. Every value rendered in the report is HTML-escaped (textContent / escapeHtml),
  and the report uses a Content Security Policy and a sandboxed iframe for HTML previews to help prevent XSS.
- The script makes no network calls and sends no data anywhere; its only output is the HTML report file.
- No credentials, tokens or access tokens are stored or validated. JWT signatures are never verified.
- HAR files and generated reports may contain sensitive data (tokens, cookies, personal data). Use
  -RedactSecrets before sharing, and share reports only through approved channels.
- Review and audit the generated HTML file before sharing it outside your organization.

.PARAMETER HarPath
Path to a single .har file. One HAR file is analyzed per run.

.PARAMETER OutputPath
Output HTML file or directory. Default: <HarName>_Report_<yyyyMMdd_HHmmss>.html next to the input.

.PARAMETER OpenReport
Opens the finished report in the default browser.

.PARAMETER RedactSecrets
Masks Authorization/Cookie/Set-Cookie/X-Api-Key/Ocp-Apim-Subscription-Key headers and client_secret, password,
code, access_token, refresh_token, id_token, SAMLResponse and assertion values (first and last 4 characters are
kept, e.g. eyJ0****Xk2Q) in URLs, headers, cookies, query strings, form/JSON bodies, JWTs and SAML messages.
Decoded JWT claims and SAML XML are withheld while redacting. In JSON bodies a "code" value is only masked
when it is 20+ characters long (so error codes stay readable). _initiator data is dropped.

.EXAMPLE
.\HAR2HTML.ps1 -HarPath .\trace.har -OpenReport

.EXAMPLE
.\HAR2HTML.ps1 -HarPath .\trace.har -RedactSecrets -OutputPath C:\Reports
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Path')]
    [string]$HarPath,

    [Alias('Output', 'OutputFolder', 'OutDir')]
    [string]$OutputPath,

    [Alias('Open')]
    [switch]$OpenReport,

    [switch]$RedactSecrets
)

begin {
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ExitCode = 0
$script:ProcessRan = $false
$script:Redact = [bool]$RedactSecrets
$script:MaxBodyBytes = [int64]5120 * 1024
$script:Epoch = New-Object System.DateTime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)

#region Template
$script:HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; frame-src blob: data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__REPORT_TITLE__</title>
<style>
:root{--bg:#fff;--fg:#111;--pane:#f0f0f0;--bd:#b5b5b5;--hd:#e6e6e6;--sel:#316ac5;--selfg:#fff;--mut:#666;--link:#0645ad;--inp:#fff;--zebra:#fafafa;--red:#c00000;--purple:#7030a0;--green:#0a7a0a;--grey:#808080;--hov:#e8f0fb;--warn:#fff4ce;--warnbd:#e0b000;--code:#f7f7f7}
body.dark{--bg:#1e1e1e;--fg:#dcdcdc;--pane:#2b2b2b;--bd:#555;--hd:#333;--sel:#264f78;--selfg:#fff;--mut:#9a9a9a;--link:#6cb0ff;--inp:#3a3a3a;--zebra:#222;--red:#ff6b6b;--purple:#c792ea;--green:#6ed26e;--grey:#999;--hov:#2a3340;--warn:#4a3f10;--warnbd:#a08000;--code:#252525}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font:12px 'Segoe UI',Tahoma,Arial,sans-serif;background:var(--bg);color:var(--fg);display:flex;flex-direction:column;overflow:hidden}
button,select,input{font:inherit;color:inherit}
button{background:var(--hd);border:1px solid var(--bd);border-radius:2px;padding:1px 7px;height:22px;cursor:pointer;white-space:nowrap}
button:hover{background:var(--hov)}
button.on{background:var(--sel);color:var(--selfg);border-color:var(--sel)}
button:disabled{opacity:.5;cursor:default}
input[type=text],input[type=search],input:not([type]),select{background:var(--inp);border:1px solid var(--bd);height:22px;padding:0 4px;border-radius:2px;min-width:0}
input.bad{border-color:#d00;background:#fdd;color:#900}
body.dark input.bad{background:#5a1f1f;color:#fcc}
#banner{background:var(--warn);border-bottom:1px solid var(--warnbd);padding:2px 8px;font-size:11px;flex:none}
#toolbar{background:var(--pane);border-bottom:1px solid var(--bd);padding:3px 6px;display:flex;flex-wrap:wrap;gap:4px 6px;align-items:center;flex:none}
#toolbar .grp{display:flex;align-items:center;gap:3px}
#title{font-weight:600;font-size:13px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:4px}
#q{width:210px}
#cnt{min-width:88px;color:var(--mut);font-size:11px}
.sp{flex:1}
#qf{background:var(--pane);border-bottom:1px solid var(--bd);padding:2px 6px;display:flex;flex-wrap:wrap;gap:4px;align-items:center;flex:none}
#qf input{width:56px}
#qf .lbl{color:var(--mut);font-size:11px}
#main{flex:1;display:flex;min-height:0;position:relative}
#left{display:flex;flex-direction:column;min-width:200px;width:52%;flex:none}
#right{flex:1;display:flex;flex-direction:column;min-width:200px;min-height:0}
.vsplit{width:5px;cursor:col-resize;background:var(--pane);border-left:1px solid var(--bd);border-right:1px solid var(--bd);flex:none}
.hsplit{height:5px;cursor:row-resize;background:var(--pane);border-top:1px solid var(--bd);border-bottom:1px solid var(--bd);flex:none}
.vsplit:hover,.hsplit:hover{background:var(--sel)}
#ltabs{display:flex;background:var(--pane);border-bottom:1px solid var(--bd);flex:none}
.tab{padding:2px 9px;border:1px solid transparent;border-bottom:none;cursor:pointer;white-space:nowrap;user-select:none;margin-top:2px;position:relative}
.tab:hover{background:var(--hov)}
.tab.on{background:var(--bg);border-color:var(--bd);font-weight:600;margin-bottom:-1px;padding-bottom:3px}
.tab .dot{display:inline-block;min-width:14px;padding:0 3px;margin-left:4px;border-radius:7px;background:#ffd400;color:#000;font-size:10px;line-height:14px;text-align:center;font-weight:700}
#gridwrap{flex:1;display:flex;flex-direction:column;min-height:0}
#ghead,#gfilter{overflow:hidden;flex:none;background:var(--hd);border-bottom:1px solid var(--bd)}
.hrow{display:flex;white-space:nowrap}
.hc{position:relative;height:22px;line-height:21px;padding:0 4px;border-right:1px solid var(--bd);overflow:hidden;text-overflow:ellipsis;font-weight:600;cursor:pointer;user-select:none;flex:none}
.hc.dragover{background:var(--hov);box-shadow:inset 2px 0 0 var(--sel)}
.hc .rz{position:absolute;right:0;top:0;bottom:0;width:6px;cursor:col-resize}
.fc{flex:none;height:24px;padding:1px 2px;border-right:1px solid var(--bd);display:flex;gap:2px;align-items:center;overflow:hidden}
.fc input{flex:1;width:100%;height:20px;font-size:11px}
.fc button{height:20px;width:100%;padding:0 2px;font-size:11px;overflow:hidden;text-overflow:ellipsis}
#gview{flex:1;overflow:auto;position:relative;outline:none;font-size:12px}
#gspacer{position:absolute;top:0;left:0;width:1px}
#grows{position:absolute;top:0;left:0}
.row{display:flex;height:20px;line-height:19px;white-space:nowrap;cursor:default;border-bottom:1px solid transparent}
.row:nth-child(even){background:var(--zebra)}
.row:hover{background:var(--hov)}
.cell{flex:none;padding:0 4px;overflow:hidden;text-overflow:ellipsis}
.cell.r{text-align:right}
.cell.c{text-align:center}
.row.sep{background:var(--hd)!important;font-weight:600;color:var(--fg)!important;font-style:normal!important;border-top:1px solid var(--bd);border-bottom:1px solid var(--bd)}
.rc .c4,.rc .c5{color:var(--red)}
.rc .c3{color:var(--purple)}
.rc .s304{color:var(--grey)}
.rc .fail{color:var(--red);font-style:italic}
.rc .t-stylesheet{color:var(--purple)}
.rc .t-script{color:var(--green)}
.rc .t-image{color:var(--grey)}
.mk-red{background:#ffc9c9!important}.mk-orange{background:#ffdcb0!important}.mk-green{background:#c8f0c8!important}.mk-blue{background:#c4dcff!important}.mk-purple{background:#e3d1f5!important}.mk-grey{background:#d4d4d4!important}
body.dark .mk-red{background:#5a2020!important}body.dark .mk-orange{background:#5a3d18!important}body.dark .mk-green{background:#1f4a1f!important}body.dark .mk-blue{background:#1d3d66!important}body.dark .mk-purple{background:#40285a!important}body.dark .mk-grey{background:#444!important}
.row.m{background:#ffff00!important;color:#000!important}
.row.sel{background:var(--sel)!important;color:var(--selfg)!important}
.row.sel.m{background:#ffff00!important;color:#000!important;outline:2px solid var(--sel);outline-offset:-2px}
.row.sel.m .cell{font-weight:600}
.row.cmp{outline:1px dashed var(--sel);outline-offset:-1px}
.ico{display:inline-block;width:18px;text-align:center;font-size:11px}
.ins-error{color:#d00}.ins-warning{color:#d08000}.ins-info{color:#1070c0}
.row.sel:not(.m) .ico,.row.sel:not(.m) .cell span{color:inherit}
#lpanel{flex:1;overflow:auto;padding:8px;min-height:0}
#lpanel h3{margin:10px 0 4px;font-size:13px}
#lpanel h3:first-child{margin-top:0}
.cards{display:flex;flex-wrap:wrap;gap:6px}
.card{border:1px solid var(--bd);background:var(--pane);border-radius:3px;padding:5px 10px;min-width:110px}
.card b{display:block;font-size:16px}
.card span{color:var(--mut);font-size:11px}
table.t{border-collapse:collapse;width:100%}
table.t td,table.t th{border:1px solid var(--bd);padding:2px 6px;text-align:left;vertical-align:top}
table.t th{background:var(--hd);font-weight:600;white-space:nowrap}
table.t td.k{white-space:nowrap;font-weight:600;width:1%;background:var(--code)}
table.t td.v{word-break:break-all;font-family:Consolas,'Courier New',monospace;font-size:12px}
table.t tr.clk{cursor:pointer}
table.t tr.clk:hover td{background:var(--hov)}
.bar{display:inline-block;height:10px;background:var(--sel);vertical-align:middle;min-width:1px}
.mono{font-family:Consolas,'Courier New',monospace;font-size:12px}
#sessbar{display:flex;align-items:center;gap:6px;background:var(--pane);border-bottom:1px solid var(--bd);padding:2px 6px;flex:none;min-height:26px}
#sessbar .info{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
#sessbar input{width:200px}
.insp{display:flex;flex-direction:column;min-height:60px;min-width:0;overflow:hidden}
.ihead{display:flex;align-items:flex-end;background:var(--pane);border-bottom:1px solid var(--bd);padding:2px 4px 0;gap:4px;flex:none}
.ihead .nm{font-weight:700;padding:0 6px 3px 2px;align-self:center}
.itabs{display:flex;flex-wrap:wrap;flex:1}
.ibtns{display:flex;gap:3px;padding-bottom:2px;align-self:center}
.ibody{flex:1;overflow:auto;padding:6px;font-family:Consolas,'Courier New',monospace;font-size:12px;outline:none;min-height:0;background:var(--bg)}
.ibody pre,.pre{margin:0;font-family:Consolas,'Courier New',monospace;font-size:12px;white-space:pre;tab-size:4}
.ibody.wrap pre,.ibody.wrap .pre,.ibody.wrap td.v{white-space:pre-wrap;word-break:break-all}
.note{padding:6px 8px;background:var(--warn);border:1px solid var(--warnbd);margin-bottom:6px;font-family:'Segoe UI',Tahoma,sans-serif}
.empty{padding:14px;color:var(--mut);font-family:'Segoe UI',Tahoma,sans-serif;font-style:italic}
mark{background:#ffff00;color:#000;padding:0}
.sec{margin:8px 0 3px;font-weight:700;font-family:'Segoe UI',Tahoma,sans-serif;background:var(--hd);padding:1px 6px;border:1px solid var(--bd)}
.sec:first-child{margin-top:0}
.tree{line-height:1.45}
.tree .n{padding-left:16px}
.tree .tg{cursor:pointer;display:inline-block;width:14px;color:var(--mut);user-select:none}
.tree .key{color:#a31515}.tree .str{color:#0b6b0b}.tree .numv{color:#0451a5}.tree .bool{color:#0000ff}.tree .nul{color:#808080}
body.dark .tree .key{color:#9cdcfe}body.dark .tree .str{color:#ce9178}body.dark .tree .numv{color:#b5cea8}body.dark .tree .bool{color:#569cd6}
.tree .more{color:var(--link);cursor:pointer}
.badge{display:inline-block;padding:0 6px;border-radius:8px;font-size:11px;font-family:'Segoe UI',sans-serif;font-weight:600;color:#fff;background:#666}
.badge.bad{background:#c00}.badge.good{background:#2a8a2a}
.jcard{border:1px solid var(--bd);margin-bottom:8px;font-family:'Segoe UI',Tahoma,sans-serif}
.jcard .jh{background:var(--hd);padding:3px 6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.jcard .jb{padding:5px}
.tw{display:flex;height:16px;border:1px solid var(--bd);margin:4px 0;background:var(--code)}
.tw div{height:100%}
.wf{display:flex;gap:6px;flex-wrap:wrap;font-family:'Segoe UI',sans-serif;margin-top:4px}
.wf i{display:inline-block;width:10px;height:10px;margin-right:3px;vertical-align:middle}
.diffgrid{width:100%;border-collapse:collapse;table-layout:fixed}
.diffgrid td{border:1px solid var(--bd);padding:1px 4px;vertical-align:top;white-space:pre-wrap;word-break:break-all;font-family:Consolas,monospace;font-size:12px}
.diffgrid tr.chg td{background:#fff3b0}.diffgrid tr.add td.b{background:#c8f0c8}.diffgrid tr.del td.a{background:#ffc9c9}
body.dark .diffgrid tr.chg td{background:#5a4d10}body.dark .diffgrid tr.add td.b{background:#1f4a1f}body.dark .diffgrid tr.del td.a{background:#5a2020}
#status{background:var(--pane);border-top:1px solid var(--bd);padding:2px 8px;font-size:11px;flex:none;display:flex;gap:14px;white-space:nowrap;overflow:hidden}
#tlwrap{position:relative;flex:1;overflow-y:auto;overflow-x:hidden;min-height:0}
#tlcv{position:sticky;top:0;display:block;width:100%}
#tlsp{position:absolute;top:0;left:0;width:1px}
.popup,#ctx{position:fixed;z-index:50;background:var(--bg);border:1px solid var(--bd);box-shadow:2px 3px 8px rgba(0,0,0,.35);padding:3px 0;min-width:160px;max-height:70vh;overflow:auto}
.popup label,.popup .mi,#ctx .mi{display:block;padding:3px 14px;cursor:pointer;white-space:nowrap}
.popup label:hover,.popup .mi:hover,#ctx .mi:hover{background:var(--sel);color:var(--selfg)}
#ctx .mi.dis{color:var(--mut);pointer-events:none}
#ctx hr{border:0;border-top:1px solid var(--bd);margin:3px 0}
.sw{display:inline-block;width:16px;height:16px;border:1px solid #666;margin:2px 3px;cursor:pointer;vertical-align:middle}
.modalbg{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:100;display:flex;align-items:center;justify-content:center}
.modal{background:var(--bg);border:1px solid var(--bd);box-shadow:0 6px 24px rgba(0,0,0,.5);max-width:94vw;max-height:90vh;width:760px;display:flex;flex-direction:column}
.modal.wide{width:94vw;height:88vh}
.modal .mh{background:var(--pane);padding:5px 10px;display:flex;align-items:center;border-bottom:1px solid var(--bd);font-weight:700}
.modal .mh span{flex:1}
.modal .mb{padding:10px;overflow:auto;flex:1}
.kbd{display:inline-block;border:1px solid var(--bd);border-bottom-width:2px;border-radius:3px;padding:0 5px;background:var(--code);font-family:Consolas,monospace;font-size:11px}
.chain .hop{padding:4px 6px;border:1px solid var(--bd);margin:3px 0;cursor:pointer;font-family:'Segoe UI',sans-serif}
.chain .hop:hover{background:var(--hov)}
.chain .hop.cur{border-color:var(--sel);box-shadow:inset 3px 0 0 var(--sel)}
.chain .arrow{text-align:center;color:var(--mut)}
.copybtn{height:18px;padding:0 5px;font-size:11px}
</style>
</head>
<body>
<div id="banner" role="alert">This report may contain sensitive data (tokens, cookies, personal data). Share it only through approved channels.</div>
<div id="toolbar">
  <span id="title">__REPORT_TITLE__</span>
  <div class="grp">
    <input id="q" type="search" placeholder="Search (Ctrl+F)" autocomplete="off" spellcheck="false" aria-label="Search">
    <button id="bCase" title="Match case">Aa</button>
    <button id="bRe" title="Regular expression">.*</button>
    <button id="bWord" title="Whole word">W</button>
    <select id="scope" title="Search scope">
      <option value="all">All</option><option value="url">URL</option><option value="reqh">Request headers</option><option value="reqb">Request body</option><option value="resh">Response headers</option><option value="resb">Response body</option>
    </select>
    <button id="bPrev" title="Previous match (Shift+F3)">&#9664;</button>
    <button id="bNext" title="Next match (F3)">&#9654;</button>
    <span id="cnt"></span>
    <label title="Hide sessions that do not match"><input type="checkbox" id="onlyM"> Show only matching sessions</label>
  </div>
  <span class="sp"></span>
  <div class="grp">
    <button id="bTime" title="Time display: Local / UTC / Relative">Local</button>
    <button id="bCols" title="Choose columns">Columns &#9662;</button>
    <button id="bPages" title="Group sessions by page">Pages</button>
    <button id="bColors" title="Toggle row colours">Colours</button>
    <button id="bRedact" title="Mask tokens, cookies and passwords on screen">Redact</button>
    <button id="bCompare" title="Compare selected session with the Ctrl+clicked one">Compare</button>
    <button id="bExport" title="Export">Export &#9662;</button>
    <button id="bDark" title="Dark mode">Dark</button>
    <button id="bHelp" title="Help (?)">?</button>
  </div>
</div>
<div id="qf">
  <span class="lbl">Quick filters:</span>
  <button data-q="errors">Errors</button>
  <button data-q="xhr">XHR/Fetch</button>
  <button data-q="doc">Document</button>
  <button data-q="static">Hide static</button>
  <button data-q="auth">Auth traffic</button>
  <button data-q="slow">Slow &gt;</button><input id="slowN" type="text" value="1000" title="milliseconds"><span class="lbl">ms</span>
  <button data-q="large">Large &gt;</button><input id="largeN" type="text" value="500" title="KB"><span class="lbl">KB</span>
  <button data-q="redir">Redirects</button>
  <button id="bClear" title="Clear all filters and search">Clear all</button>
</div>
<div id="main">
  <div id="left">
    <div id="ltabs"></div>
    <div id="gridwrap">
      <div id="ghead"></div>
      <div id="gfilter"></div>
      <div id="gview" tabindex="0"><div id="gspacer"></div><div id="grows" class="rc"></div></div>
    </div>
    <div id="lpanel" style="display:none"></div>
  </div>
  <div class="vsplit" id="vsplit" title="Drag to resize"></div>
  <div id="right">
    <div id="sessbar"><span class="info" id="sbInfo">No session selected</span>
      <select id="sbMark" title="Mark colour"><option value="">No mark</option><option value="red">Red</option><option value="orange">Orange</option><option value="green">Green</option><option value="blue">Blue</option><option value="purple">Purple</option><option value="grey">Grey</option></select>
      <input id="sbNote" type="text" placeholder="Note..." maxlength="500"></div>
    <div class="insp" id="reqPane"></div>
    <div class="hsplit" id="hsplit" title="Drag to resize"></div>
    <div class="insp" id="respPane"></div>
  </div>
</div>
<div id="status"></div>
<div id="ctx" style="display:none"></div>
<script type="application/json" id="har-data">__HAR_DATA__</script>
<script>
(function(){
'use strict';
const $=(s,r)=>(r||document).querySelector(s);
function add(n,c){
  if(c==null||c===false)return;
  if(Array.isArray(c)){c.forEach(x=>add(n,x));return;}
  n.appendChild(typeof c==='object'?c:document.createTextNode(String(c)));
}
function el(tag,attrs){
  const n=document.createElement(tag);
  if(attrs){
    for(const k in attrs){
      const v=attrs[k];
      if(v==null||v===false)continue;
      if(k==='class')n.className=v;
      else if(k==='text')n.textContent=v;
      else if(k==='style')n.style.cssText=v;
      else if(k.slice(0,2)==='on'){if(typeof v==='function')n.addEventListener(k.slice(2),v);}
      else n.setAttribute(k,v===true?'':String(v));
    }
  }
  for(let i=2;i<arguments.length;i++)add(n,arguments[i]);
  return n;
}
const LS={
  get(k,d){try{const v=localStorage.getItem(k);return v==null?d:JSON.parse(v);}catch(e){return d;}},
  set(k,v){try{localStorage.setItem(k,JSON.stringify(v));}catch(e){}}
};
const str=v=>v==null?'':(typeof v==='object'?JSON.stringify(v):String(v));
const num=v=>{v=Number(v);return isFinite(v)?v:0;};
const p2=n=>(n<10?'0':'')+n;
const p3=n=>(n<10?'00':n<100?'0':'')+n;
const tick=()=>new Promise(r=>setTimeout(r,0));
function fmtBytes(n){
  n=num(n);
  if(n<1024)return n+' B';
  if(n<1048576)return (n/1024).toFixed(1)+' KB';
  if(n<1073741824)return (n/1048576).toFixed(2)+' MB';
  return (n/1073741824).toFixed(2)+' GB';
}
function fmtMs(n){n=num(n);return n>=1000?(n/1000).toFixed(2)+' s':Math.round(n)+' ms';}
function fmtTs(ms,tz){
  if(!isFinite(ms)||ms<=0)return '';
  const d=new Date(ms),u=tz==='UTC';
  const g=n=>u?d['getUTC'+n]():d['get'+n]();
  return g('FullYear')+'-'+p2(g('Month')+1)+'-'+p2(g('Date'))+' '+p2(g('Hours'))+':'+p2(g('Minutes'))+':'+p2(g('Seconds'))+'.'+p3(g('Milliseconds'));
}
function debounce(fn,ms){let t;return function(){const a=arguments;clearTimeout(t);t=setTimeout(()=>fn.apply(null,a),ms);};}

let D;
try{D=JSON.parse($('#har-data').textContent);}
catch(err){document.body.textContent='Failed to read embedded report data: '+err.message;return;}
const meta=(D&&D.meta)||{};
const E=Array.isArray(D&&D.entries)?D.entries:[];
const N=E.length;
const RK='harrep:'+str(meta.sourceFile)+'|'+str(meta.generatedAt);
(function(){
  const g=new Date(meta.generatedAt);
  if(isNaN(g.getTime()))return;
  const p=n=>String(n).padStart(2,'0');
  const s=g.getFullYear()+'-'+p(g.getMonth()+1)+'-'+p(g.getDate())+' '+p(g.getHours())+':'+p(g.getMinutes())+':'+p(g.getSeconds());
  const t=$('#title');
  if(t){t.title=t.textContent;const sp=document.createElement('span');sp.id='gen';sp.textContent='Generated: '+s;sp.style.cssText='font-size:11px;opacity:.75;margin-right:8px;white-space:nowrap';t.parentNode.insertBefore(sp,t.nextSibling);}
})();
const pagesMeta=Array.isArray(meta.pages)?meta.pages:[];
const pageIdxById={};
pagesMeta.forEach((p,i)=>{if(p&&p.id!=null)pageIdxById[p.id]=i;});

function hget(list,name){
  if(!Array.isArray(list))return '';
  name=name.toLowerCase();
  for(const h of list){if(h&&String(h.name).toLowerCase()===name)return str(h.value);}
  return '';
}
const AUTH_RE=/login\.microsoftonline\.com|login\.live\.com|login\.windows\.net|sts\.windows\.net|\/adfs\/|\/oauth2?\/|\/saml|\/wsfed|\/\.well-known\/openid|\/connect\/(?:token|authorize)|\/authorize\b/i;
const SEV={error:3,warning:2,info:1};
function prep(e,i){
  e._i=i;
  if(e.id==null)e.id=i+1;
  const sm=e.startedMs;
  e._t=(sm!=null&&isFinite(+sm))?+sm:(Date.parse(e.startedDateTime)||0);
  const tm=e.timings||{};
  let d=num(tm.total);
  if(d<=0){d=0;['blocked','dns','connect','send','wait','receive'].forEach(k=>{const v=num(tm[k]);if(v>0)d+=v;});}
  e._dur=d;
  const rb=e.respBody||{};
  e._size=num(rb.size!=null?rb.size:(e._contentSize||0));
  e._xfer=e._transferSize!=null?num(e._transferSize):(rb.compressedSize!=null?num(rb.compressedSize):-1);
  e._status=num(e.status);
  e._fail=e._status===0||!!e.error;
  e.url=str(e.url);
  e.method=str(e.method);
  e.reqHeaders=Array.isArray(e.reqHeaders)?e.reqHeaders:[];
  e.respHeaders=Array.isArray(e.respHeaders)?e.respHeaders:[];
  e._ct=str(e.mimeType)||hget(e.respHeaders,'content-type');
  const cv=[];
  if(e.correlation&&typeof e.correlation==='object'){for(const k in e.correlation){const v=str(e.correlation[k]);if(v)cv.push(v);}}
  e._corr=cv.join(' ');
  e._corr1=cv[0]||'';
  let mx=0;
  (Array.isArray(e.insights)?e.insights:[]).forEach(x=>{const r=SEV[x&&x.severity]||1;if(r>mx)mx=r;});
  e._insMax=mx;
  e._cache=e.fromCache?'Cache':(e._status===304?'304':'');
  e._auth=AUTH_RE.test(e.url);
  e._page=e.pageRef!=null&&pageIdxById[e.pageRef]!=null?pageIdxById[e.pageRef]:-1;
}
E.forEach(prep);
let firstMs=0;
{let m=Infinity;E.forEach(e=>{if(e._t>0&&e._t<m)m=e._t;});firstMs=isFinite(m)?m:0;}
const idToIdx=new Map();
E.forEach(e=>{if(!idToIdx.has(String(e.id)))idToIdx.set(String(e.id),e._i);});

const UI=Object.assign({theme:'light',colors:true,redact:false,pages:false,tz:'Local',leftPx:0,reqFrac:0.5,vis:null,widths:{},order:null,wrap:false,jsonView:'tree'},LS.get('harui:v1',{}));
const saveUI=()=>LS.set('harui:v1',UI);
let marks=LS.get(RK+':marks',{});
const saveMarks=()=>LS.set(RK+':marks',marks);

const COLS=[
 {k:'num',l:'#',w:48,al:'r'},
 {k:'time',l:'Date/Time',w:158,req:1},
 {k:'method',l:'Method',w:64,req:1},
 {k:'status',l:'Result',w:56,al:'c',req:1},
 {k:'host',l:'Host',w:150},
 {k:'proto',l:'Protocol',w:62},
 {k:'url',l:'URL',w:420,req:1},
 {k:'ctype',l:'Content-Type',w:130},
 {k:'rtype',l:'Type',w:70},
 {k:'size',l:'Size (body / transfer)',w:128,al:'r'},
 {k:'dur',l:'Duration',w:72,al:'r'},
 {k:'ip',l:'Server IP',w:100},
 {k:'cache',l:'Cache',w:60},
 {k:'corr',l:'Correlation ID',w:170},
 {k:'ins',l:'!',w:26,al:'c'}
];
const COLBY={};COLS.forEach(c=>COLBY[c.k]=c);
const DEFVIS=['num','time','method','status','host','url','rtype','size','dur','ins'];
if(!Array.isArray(UI.vis))UI.vis=DEFVIS.slice();
COLS.forEach(c=>{if(c.req&&UI.vis.indexOf(c.k)<0)UI.vis.push(c.k);});
if(!Array.isArray(UI.order)||UI.order.length!==COLS.length||COLS.some(c=>UI.order.indexOf(c.k)<0))UI.order=COLS.map(c=>c.k);
const colW=k=>num(UI.widths[k])||COLBY[k].w;
const visCols=()=>UI.order.filter(k=>UI.vis.indexOf(k)>=0);

/* ---------- redaction (display only) ---------- */
const SENS_H=/^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|ocp-apim-subscription-key|x-auth-token|x-csrf-token)$/i;
const SENS_K=/^(client_secret|password|passwd|pwd|code|access_token|refresh_token|id_token|samlresponse|samlrequest|assertion|client_assertion|token|secret|api[_-]?key)$/i;
function mask(s){s=str(s);if(s.length<=8)return '****';return s.slice(0,4)+'****'+s.slice(-4);}
function redactHeader(name,value){
  if(!UI.redact)return value;
  value=str(value);
  if(/^(set-)?cookie$/i.test(name)){
    return value.split(/;\s*/).map((p,i)=>{
      const q=p.indexOf('=');
      if(q<0)return p;
      const k=p.slice(0,q);
      if(/^(domain|path|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i.test(k))return p;
      return k+'='+mask(p.slice(q+1));
    }).join('; ');
  }
  if(SENS_H.test(name)){
    const m=/^(Bearer|Basic|Negotiate|NTLM|Digest)\s+(.+)$/i.exec(value);
    return m?m[1]+' '+mask(m[2]):mask(value);
  }
  return value;
}
function redactVal(name,value){return UI.redact&&SENS_K.test(name)?mask(value):value;}
function redactText(s){
  if(!UI.redact||!s)return s;
  s=String(s);
  s=s.replace(/eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*/g,m=>mask(m));
  s=s.replace(/([?&;\s]|^)(client_secret|password|passwd|code|access_token|refresh_token|id_token|SAMLResponse|SAMLRequest|assertion|client_assertion)=([^&\s"'<>]+)/gi,(m,a,b,c)=>a+b+'='+mask(c));
  s=s.replace(/("(?:client_secret|password|passwd|access_token|refresh_token|id_token|assertion|SAMLResponse|code|client_assertion)"\s*:\s*")([^"]*)(")/gi,(m,a,b,c)=>a+mask(b)+c);
  s=s.replace(/(<(?:saml2?p?:)?(?:Assertion|SAMLResponse)\b[^>]*>)([\s\S]{20,}?)(<\/)/gi,(m,a,b,c)=>a+mask(b)+c);
  return s;
}

/* ---------- time ---------- */
function fmtTime(e){
  if(UI.tz==='Relative'){return '+'+Math.round(e._t-firstMs)+' ms';}
  return fmtTs(e._t,UI.tz)||str(e.startedDateTime);
}
function fmtEpoch(sec){
  const ms=num(sec)*1000;
  return fmtTs(ms,UI.tz==='UTC'?'UTC':'Local')+(UI.tz==='UTC'?' UTC':'');
}

/* ---------- search texts ---------- */
const SC_ALL=['url','reqh','reqb','resh','resb','auth'];
function hdrText(l){return (Array.isArray(l)?l:[]).map(h=>str(h&&h.name)+': '+str(h&&h.value)).join('\n');}
function bodyAll(b){
  if(!b)return '';
  let s=str(b.raw);
  const d=str(b.decoded);
  if(d&&d!==s)s+='\n'+d;
  if(Array.isArray(b.parts))b.parts.forEach(p=>{s+='\n'+hdrText(p&&p.headers)+'\n'+str(p&&p.text);});
  if(Array.isArray(b.params))b.params.forEach(p=>{s+='\n'+str(p&&p.name)+'='+str(p&&p.value);});
  return s;
}
function authText(e){
  const a=e.auth;
  if(!a||typeof a!=='object')return '';
  let s='';
  (a.jwt||[]).forEach(j=>{s+=JSON.stringify(j&&j.header)+'\n'+JSON.stringify(j&&j.payload)+'\n';});
  (a.saml||[]).forEach(x=>{s+=str(x&&x.xml)+'\n'+str(x&&x.issuer)+' '+str(x&&x.nameId)+' '+str(x&&x.audience)+'\n';});
  if(a.oauthParams)for(const k in a.oauthParams)s+=k+'='+str(a.oauthParams[k])+'\n';
  return s;
}
function scopeText(e,s){
  switch(s){
    case 'url':return e.url;
    case 'reqh':return hdrText(e.reqHeaders)+'\n'+(Array.isArray(e.reqCookies)?e.reqCookies.map(c=>str(c.name)+'='+str(c.value)).join('\n'):'');
    case 'reqb':return bodyAll(e.reqBody);
    case 'resh':return hdrText(e.respHeaders);
    case 'resb':return bodyAll(e.respBody)+(Array.isArray(e.wsMessages)?'\n'+e.wsMessages.map(m=>str(m&&m.data)).join('\n'):'');
    case 'auth':return authText(e);
  }
  return '';
}
const TXT={},TXL={},TXP={},TXLP={};
function ensureText(s){
  if(TXP[s])return TXP[s];
  return TXP[s]=(async function(){
    const arr=new Array(N);let t0=performance.now();
    for(let i=0;i<N;i++){
      arr[i]=scopeText(E[i],s);
      if(performance.now()-t0>12){await tick();t0=performance.now();}
    }
    TXT[s]=arr;
  })();
}
function ensureLower(s){
  if(TXLP[s])return TXLP[s];
  return TXLP[s]=(async function(){
    await ensureText(s);
    const arr=new Array(N);let t0=performance.now();
    for(let i=0;i<N;i++){
      arr[i]=TXT[s][i].toLowerCase();
      if(performance.now()-t0>12){await tick();t0=performance.now();}
    }
    TXL[s]=arr;
  })();
}

/* ---------- search state ---------- */
const S={q:'',cs:false,re:false,word:false,scope:'all',onlyM:false};
let MATCH=null,reHL=null,searchToken=0;
function buildRe(global){
  let src=S.q;
  if(!S.re)src=src.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  if(S.word)src='(?<![\\w])(?:'+src+')(?![\\w])';
  return new RegExp(src,(S.cs?'':'i')+(global?'g':''));
}
async function runSearch(user){
  const my=++searchToken;
  const qi=$('#q');
  qi.classList.remove('bad');
  if(!S.q){MATCH=null;reHL=null;searchDone(false);return;}
  let re;
  try{re=buildRe(false);reHL=buildRe(true);}
  catch(err){qi.classList.add('bad');MATCH=null;reHL=null;searchDone(false);return;}
  const scopes=S.scope==='all'?SC_ALL:[S.scope];
  const plain=!S.re&&!S.word&&!S.cs;
  $('#cnt').textContent='Searching...';
  for(const s of scopes){await (plain?ensureLower(s):ensureText(s));if(my!==searchToken)return;}
  const ql=S.q.toLowerCase();
  const M=new Uint8Array(N);
  let t0=performance.now();
  for(let i=0;i<N;i++){
    for(let k=0;k<scopes.length;k++){
      const t=plain?TXL[scopes[k]][i]:TXT[scopes[k]][i];
      if(!t)continue;
      if(plain?t.indexOf(ql)>=0:re.test(t)){M[i]=1;break;}
    }
    if(performance.now()-t0>12){await tick();if(my!==searchToken)return;t0=performance.now();}
  }
  MATCH=M;
  searchDone(!!user);
}
function hlRe(scope){
  if(!reHL)return null;
  if(S.scope==='all'||S.scope===scope)return reHL;
  return null;
}

/* ---------- filters ---------- */
const F={text:{},method:new Set(),cls:new Set(),exact:'',tFrom:'',tTo:'',dMin:'',dMax:'',sMin:'',sMax:'',ins:false};
const Q={errors:false,xhr:false,doc:false,static:false,auth:false,slow:false,large:false,redir:false,slowN:1000,largeKB:500};
function parseSize(s){
  const m=/^\s*([\d.]+)\s*(b|k|kb|m|mb)?\s*$/i.exec(s||'');
  if(!m)return null;
  const u=(m[2]||'b').toLowerCase();
  return parseFloat(m[1])*(u==='b'?1:u[0]==='k'?1024:1048576);
}
function parseNum(s){const v=parseFloat(s);return isFinite(v)?v:null;}
function parseTs(s,end){
  s=(s||'').trim();
  if(!s)return null;
  if(UI.tz==='Relative'){const v=parseFloat(s);return isFinite(v)?firstMs+v:null;}
  const m=/^(\d{4})-(\d\d)-(\d\d)(?:[ T](\d\d):(\d\d)(?::(\d\d)(?:\.(\d{1,3}))?)?)?$/.exec(s);
  if(!m)return null;
  const hasT=m[4]!=null;
  const a=[+m[1],+m[2]-1,+m[3],+(m[4]||0),+(m[5]||0),+(m[6]||0),+(m[7]?(m[7]+'00').slice(0,3):0)];
  let v=UI.tz==='UTC'?Date.UTC.apply(null,a):new Date(a[0],a[1],a[2],a[3],a[4],a[5],a[6]).getTime();
  if(end&&!hasT)v+=86399999;
  return v;
}
function colText(e,k){
  switch(k){
    case 'num':return str(e.id);
    case 'host':return str(e.host);
    case 'proto':return str(e.httpVersion);
    case 'url':return e.url;
    case 'ctype':return e._ct;
    case 'rtype':return str(e.resourceType);
    case 'ip':return str(e.serverIp);
    case 'cache':return e._cache;
  }
  return '';
}
const TEXTCOLS=['num','host','proto','url','ctype','rtype','ip','cache','corr'];
function compileFilters(){
  const tf=[];
  TEXTCOLS.forEach(k=>{
    let v=(F.text[k]||'').trim().toLowerCase();
    if(!v)return;
    let neg=false;
    if(v[0]==='!'){neg=true;v=v.slice(1);if(!v)return;}
    tf.push({k,v,neg});
  });
  const exact=F.exact.split(/[\s,]+/).filter(Boolean).map(Number).filter(isFinite);
  return {
    tf,exact,
    tFrom:parseTs(F.tFrom,false),tTo:parseTs(F.tTo,true),
    dMin:parseNum(F.dMin),dMax:parseNum(F.dMax),
    sMin:parseSize(F.sMin),sMax:parseSize(F.sMax),
    slowN:num(Q.slowN),largeB:num(Q.largeKB)*1024
  };
}
function passes(e,c){
  if(Q.errors&&!(e._status>=400||e._fail))return false;
  if(Q.xhr&&e.resourceType!=='xhr'&&e.resourceType!=='fetch')return false;
  if(Q.doc&&e.resourceType!=='document')return false;
  if(Q.static&&e.isStatic)return false;
  if(Q.auth&&!e._auth)return false;
  if(Q.slow&&!(e._dur>c.slowN))return false;
  if(Q.large&&!(Math.max(e._size,e._xfer)>c.largeB))return false;
  if(Q.redir&&!(e._status>=300&&e._status<400))return false;
  if(F.ins&&!e._insMax)return false;
  if(F.method.size&&!F.method.has(String(e.method).toUpperCase()))return false;
  if(F.cls.size||c.exact.length){
    const s=e._status;
    let ok=c.exact.indexOf(s)>=0;
    if(!ok&&F.cls.size){
      if(s===0||e._fail){ok=F.cls.has('fail');}
      if(!ok&&s>0)ok=F.cls.has(Math.floor(s/100)+'xx');
    }
    if(!ok)return false;
  }
  for(let i=0;i<c.tf.length;i++){
    const f=c.tf[i];
    const t=(f.k==='corr'?e._corr:colText(e,f.k)).toLowerCase();
    if((t.indexOf(f.v)>=0)===f.neg)return false;
  }
  if(c.tFrom!=null&&e._t<c.tFrom)return false;
  if(c.tTo!=null&&e._t>c.tTo)return false;
  if(c.dMin!=null&&e._dur<c.dMin)return false;
  if(c.dMax!=null&&e._dur>c.dMax)return false;
  if(c.sMin!=null&&e._size<c.sMin)return false;
  if(c.sMax!=null&&e._size>c.sMax)return false;
  return true;
}
const sort={k:'num',dir:1};
function sortVal(e,k){
  switch(k){
    case 'num':return e._i;
    case 'time':return e._t;
    case 'status':return e._status;
    case 'size':return e._size;
    case 'dur':return e._dur;
    case 'ins':return e._insMax;
    case 'method':return e.method;
    case 'corr':return e._corr1;
    case 'ctype':return e._ct;
  }
  return colText(e,k).toLowerCase();
}


/* ---------- view (filter + sort + group) ---------- */
let view=[],posOf=new Int32Array(N),matchPos=[],selI=-1,cmpI=-1;
const RH=20;
function applyView(){
  const c=compileFilters();
  let idx=[];
  const useM=S.onlyM&&MATCH;
  for(let i=0;i<N;i++){
    if(useM&&!MATCH[i])continue;
    if(passes(E[i],c))idx.push(i);
  }
  if(!(sort.k==='num'&&sort.dir===1)){
    const k=sort.k,d=sort.dir;
    idx.sort((a,b)=>{const x=sortVal(E[a],k),y=sortVal(E[b],k);return x<y?-d:x>y?d:a-b;});
  }
  if(UI.pages&&pagesMeta.length){
    const buckets=new Map();
    idx.forEach(i=>{const p=E[i]._page;if(!buckets.has(p))buckets.set(p,[]);buckets.get(p).push(i);});
    const out=[];
    const order=[];
    for(let p=0;p<pagesMeta.length;p++)order.push(p);
    order.push(-1);
    order.forEach(p=>{const b=buckets.get(p);if(b&&b.length){out.push(-(p+2));for(const i of b)out.push(i);}});
    idx=out;
  }
  view=idx;
  posOf=new Int32Array(N).fill(-1);
  matchPos=[];
  for(let p=0;p<view.length;p++){
    const i=view[p];
    if(i<0)continue;
    posOf[i]=p;
    if(MATCH&&MATCH[i])matchPos.push(p);
  }
  gspacer.style.height=(view.length*RH)+'px';
  renderGrid(true);
  updateStatus();
  updateCounter();
  panelsDirty=true;
  if(leftTab!=='sessions')renderPanel(leftTab);
}
const viewEntries=()=>view.filter(i=>i>=0).map(i=>E[i]);

/* ---------- grid ---------- */
const gview=$('#gview'),grows=$('#grows'),gspacer=$('#gspacer'),ghead=$('#ghead'),gfilter=$('#gfilter');
let lastFirst=-1,lastLast=-1;
const totalW=()=>visCols().reduce((a,k)=>a+colW(k),0);
const TYPE_ICON={document:'\u{1F4C4}',stylesheet:'\u{1F3A8}',script:'JS',xhr:'\u21C4',fetch:'\u21C4',image:'\u{1F5BC}',font:'Aa',media:'\u25B6',websocket:'\u{1F50C}',other:'\u2022'};
const INS_ICON={error:'\u2716',warning:'\u26A0',info:'\u2139'};
const MARKS=['red','orange','green','blue','purple','grey'];
const MARK_RGB={red:'#ff9a9a',orange:'#ffc98a',green:'#9fe09f',blue:'#9cc4ff',purple:'#cfaff0',grey:'#bdbdbd'};
function rowClass(e){
  if(!UI.colors)return '';
  if(e._fail)return 'fail';
  const s=e._status;
  if(s>=500)return 'c5';
  if(s>=400)return 'c4';
  if(s===304)return 's304';
  if(s>=300)return 'c3';
  const t=e.resourceType;
  if(t==='stylesheet'||t==='script'||t==='image')return 't-'+t;
  return '';
}
function cellText(e,k){
  switch(k){
    case 'num':return str(e.id);
    case 'time':return fmtTime(e);
    case 'method':return e.method;
    case 'status':return e._status?String(e._status):(e._fail?'0':'');
    case 'host':return str(e.host);
    case 'proto':return str(e.httpVersion);
    case 'url':return redactText(e.url);
    case 'ctype':return e._ct;
    case 'rtype':return str(e.resourceType);
    case 'size':return fmtBytes(e._size)+(e._xfer>=0?' / '+fmtBytes(e._xfer):'');
    case 'dur':return e._dur?Math.round(e._dur)+' ms':'';
    case 'ip':return str(e.serverIp);
    case 'cache':return e._cache;
    case 'corr':return e._corr1;
  }
  return '';
}
function buildRow(pos,cols){
  const item=view[pos];
  if(item<0){
    const p=-item-2;
    const pg=p>=0?pagesMeta[p]:null;
    let cnt=0;
    for(let q=pos+1;q<view.length&&view[q]>=0;q++)cnt++;
    const r=el('div',{class:'row sep','data-pos':pos,style:'width:'+totalW()+'px'});
    r.appendChild(el('div',{class:'cell',style:'width:100%'},'\u25A0 '+(pg?(str(pg.title)||str(pg.id)):'(no page)')+'  ('+cnt+')'+(pg&&pg.startedDateTime?'  '+str(pg.startedDateTime):'')));
    return r;
  }
  const e=E[item];
  const mk=marks[e.id];
  let cls='row';
  const rc=rowClass(e);
  if(rc)cls+=' '+rc;
  if(MATCH&&MATCH[item])cls+=' m';
  if(item===selI)cls+=' sel';
  if(item===cmpI)cls+=' cmp';
  if(mk&&mk.c&&MARKS.indexOf(mk.c)>=0)cls+=' mk-'+mk.c;
  const r=el('div',{class:cls,'data-pos':pos});
  cols.forEach(k=>{
    const c=COLBY[k];
    const cell=el('div',{class:'cell'+(c.al==='r'?' r':c.al==='c'?' c':''),style:'width:'+colW(k)+'px'});
    if(k==='ins'){
      if(e._insMax){
        const sev=e._insMax===3?'error':e._insMax===2?'warning':'info';
        cell.appendChild(el('span',{class:'ins-'+sev,title:e.insights.map(x=>str(x&&x.message)).join('\n')},INS_ICON[sev]));
      }
    }else if(k==='url'){
      cell.appendChild(el('span',{class:'ico'},TYPE_ICON[e.resourceType]||TYPE_ICON.other));
      cell.appendChild(document.createTextNode(cellText(e,k)));
      cell.title=e.url;
    }else if(k==='num'){
      cell.textContent=(mk&&mk.n?'\u270E ':'')+str(e.id);
    }else{
      cell.textContent=cellText(e,k);
    }
    r.appendChild(cell);
  });
  return r;
}
function renderGrid(force){
  const vh=gview.clientHeight,st=gview.scrollTop;
  const first=Math.max(0,Math.floor(st/RH)-6),last=Math.min(view.length,Math.ceil((st+vh)/RH)+6);
  if(!force&&first===lastFirst&&last===lastLast)return;
  lastFirst=first;lastLast=last;
  const cols=visCols();
  const w=totalW();
  gspacer.style.width=w+'px';
  grows.style.width=w+'px';
  grows.style.transform='translateY('+(first*RH)+'px)';
  const frag=document.createDocumentFragment();
  for(let p=first;p<last;p++)frag.appendChild(buildRow(p,cols));
  grows.textContent='';
  grows.appendChild(frag);
}
function ensureVisible(pos){
  const top=pos*RH,vh=gview.clientHeight;
  if(top<gview.scrollTop)gview.scrollTop=top;
  else if(top+RH>gview.scrollTop+vh)gview.scrollTop=top+RH-vh;
}
let scrollRaf=0;
gview.addEventListener('scroll',()=>{
  ghead.scrollLeft=gview.scrollLeft;gfilter.scrollLeft=gview.scrollLeft;
  if(scrollRaf)return;
  scrollRaf=requestAnimationFrame(()=>{scrollRaf=0;renderGrid(false);});
});
grows.addEventListener('click',ev=>{
  const r=ev.target.closest('.row');
  if(!r)return;
  const item=view[+r.getAttribute('data-pos')];
  if(item==null||item<0)return;
  if(ev.ctrlKey||ev.metaKey){cmpI=cmpI===item?-1:item;renderGrid(true);return;}
  select(item,{scroll:false,now:true});
  gview.focus();
});
grows.addEventListener('contextmenu',ev=>{
  const r=ev.target.closest('.row');
  if(!r)return;
  const item=view[+r.getAttribute('data-pos')];
  if(item==null||item<0)return;
  ev.preventDefault();
  openCtx(ev.clientX,ev.clientY,E[item]);
});
function buildHeader(){
  const cols=visCols();
  const hr=el('div',{class:'hrow',style:'width:'+(totalW()+24)+'px'});
  cols.forEach(k=>{
    const c=COLBY[k];
    const h=el('div',{class:'hc',style:'width:'+colW(k)+'px',draggable:'true',title:'Click to sort, drag to reorder'},c.l+(sort.k===k?(sort.dir>0?' \u25B2':' \u25BC'):''));
    h.addEventListener('click',()=>{
      if(sort.k===k)sort.dir=-sort.dir;else{sort.k=k;sort.dir=1;}
      applyView();buildHeader();
    });
    h.addEventListener('dragstart',ev=>{ev.dataTransfer.setData('text/plain',k);});
    h.addEventListener('dragover',ev=>{ev.preventDefault();h.classList.add('dragover');});
    h.addEventListener('dragleave',()=>h.classList.remove('dragover'));
    h.addEventListener('drop',ev=>{
      ev.preventDefault();h.classList.remove('dragover');
      const from=ev.dataTransfer.getData('text/plain');
      if(!COLBY[from]||from===k)return;
      const o=UI.order.filter(x=>x!==from);
      o.splice(o.indexOf(k),0,from);
      UI.order=o;saveUI();layoutGrid();
    });
    const rz=el('div',{class:'rz',draggable:'false'});
    rz.addEventListener('mousedown',ev=>{
      ev.preventDefault();ev.stopPropagation();
      const x0=ev.clientX,w0=colW(k);
      const mv=e2=>{UI.widths[k]=Math.max(28,w0+e2.clientX-x0);h.style.width=UI.widths[k]+'px';};
      const up=()=>{document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);saveUI();layoutGrid();};
      document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);
    });
    rz.addEventListener('click',ev=>ev.stopPropagation());
    h.appendChild(rz);
    hr.appendChild(h);
  });
  hr.appendChild(el('div',{style:'width:24px;flex:none'}));
  ghead.textContent='';ghead.appendChild(hr);
  ghead.scrollLeft=gview.scrollLeft;
}
const doFilter=debounce(()=>applyView(),200);
function mkInput(ph,get,set,title){
  const i=el('input',{type:'text',placeholder:ph,title:title||'',value:get()});
  i.addEventListener('input',()=>{set(i.value);doFilter();});
  return i;
}
function buildFilter(){
  const cols=visCols();
  const fr=el('div',{class:'hrow',style:'width:'+(totalW()+24)+'px'});
  cols.forEach(k=>{
    const fc=el('div',{class:'fc',style:'width:'+colW(k)+'px'});
    if(TEXTCOLS.indexOf(k)>=0){
      fc.appendChild(mkInput('contains',()=>F.text[k]||'',v=>{F.text[k]=v;},'Contains; prefix with ! to exclude'));
      fc.firstChild.value=F.text[k]||'';
    }else if(k==='time'){
      fc.appendChild(mkInput('from',()=>F.tFrom,v=>{F.tFrom=v;},'From: yyyy-MM-dd HH:mm:ss (display time zone) or ms offset in Relative mode'));
      fc.appendChild(mkInput('to',()=>F.tTo,v=>{F.tTo=v;},'To'));
    }else if(k==='dur'){
      fc.appendChild(mkInput('min',()=>F.dMin,v=>{F.dMin=v;},'Minimum ms'));
      fc.appendChild(mkInput('max',()=>F.dMax,v=>{F.dMax=v;},'Maximum ms'));
    }else if(k==='size'){
      fc.appendChild(mkInput('min',()=>F.sMin,v=>{F.sMin=v;},'Minimum body size (e.g. 10k, 2m)'));
      fc.appendChild(mkInput('max',()=>F.sMax,v=>{F.sMax=v;},'Maximum body size'));
    }else if(k==='method'){
      const b=el('button',{title:'Filter by method'},F.method.size?Array.from(F.method).join(','):'All');
      b.addEventListener('click',ev=>{
        ev.stopPropagation();
        const ms=Array.from(new Set(E.map(e=>String(e.method).toUpperCase()))).sort();
        showPopup(b,()=>el('div',null,ms.map(m=>{
          const cb=el('input',{type:'checkbox'});cb.checked=F.method.has(m);
          cb.addEventListener('change',()=>{cb.checked?F.method.add(m):F.method.delete(m);b.textContent=F.method.size?Array.from(F.method).join(','):'All';applyView();});
          return el('label',null,cb,' '+m);
        })));
      });
      fc.appendChild(b);
    }else if(k==='status'){
      const lab=()=>(F.cls.size||F.exact)?Array.from(F.cls).join(',')+(F.exact?(F.cls.size?',':'')+F.exact:''):'All';
      const b=el('button',{title:'Filter by status class / exact code'},lab());
      b.addEventListener('click',ev=>{
        ev.stopPropagation();
        showPopup(b,()=>{
          const box=el('div');
          [['1xx','1xx'],['2xx','2xx'],['3xx','3xx'],['4xx','4xx'],['5xx','5xx'],['fail','Failed / 0']].forEach(x=>{
            const cb=el('input',{type:'checkbox'});cb.checked=F.cls.has(x[0]);
            cb.addEventListener('change',()=>{cb.checked?F.cls.add(x[0]):F.cls.delete(x[0]);b.textContent=lab();applyView();});
            box.appendChild(el('label',null,cb,' '+x[1]));
          });
          const ex=el('input',{type:'text',placeholder:'exact codes: 401,403',value:F.exact,style:'margin:3px 8px;width:140px'});
          ex.addEventListener('input',()=>{F.exact=ex.value;b.textContent=lab();doFilter();});
          box.appendChild(ex);
          return box;
        });
      });
      fc.appendChild(b);
    }else if(k==='ins'){
      const b=el('button',{title:'Only sessions with insights',class:F.ins?'on':''},'!');
      b.addEventListener('click',()=>{F.ins=!F.ins;b.classList.toggle('on',F.ins);applyView();});
      fc.appendChild(b);
    }
    fr.appendChild(fc);
  });
  fr.appendChild(el('div',{style:'width:24px;flex:none'}));
  gfilter.textContent='';gfilter.appendChild(fr);
  gfilter.scrollLeft=gview.scrollLeft;
}
function layoutGrid(){buildHeader();buildFilter();renderGrid(true);}

/* ---------- popups / toast / modal ---------- */
let popupEl=null;
function closePopup(){if(popupEl){popupEl.remove();popupEl=null;}}
function showPopup(anchor,build){
  closePopup();
  const p=el('div',{class:'popup'},build());
  document.body.appendChild(p);
  const r=anchor.getBoundingClientRect();
  p.style.left=Math.max(0,Math.min(r.left,window.innerWidth-p.offsetWidth-4))+'px';
  p.style.top=Math.min(r.bottom+1,window.innerHeight-p.offsetHeight-4)+'px';
  popupEl=p;
}
document.addEventListener('mousedown',ev=>{
  if(popupEl&&!popupEl.contains(ev.target))closePopup();
  const c=$('#ctx');
  if(c.style.display!=='none'&&!c.contains(ev.target))c.style.display='none';
});
function toast(msg){
  const t=el('div',{style:'position:fixed;right:14px;bottom:34px;background:#333;color:#fff;padding:6px 12px;border-radius:3px;z-index:300;font-size:12px'},msg);
  document.body.appendChild(t);
  setTimeout(()=>t.remove(),1800);
}
function copyText(text){
  const done=()=>toast('Copied to clipboard');
  const fb=()=>{
    const ta=el('textarea',{style:'position:fixed;left:-999px;top:0'});
    ta.value=text;document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');done();}catch(e){toast('Copy failed');}
    ta.remove();
  };
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,fb);}else fb();
}
let modalEl=null;
function closeModal(){if(modalEl){modalEl.remove();modalEl=null;}}
function openModal(title,content,wide){
  closeModal();
  const bg=el('div',{class:'modalbg'});
  const m=el('div',{class:'modal'+(wide?' wide':''),role:'dialog'},
    el('div',{class:'mh'},el('span',null,title),el('button',{onclick:closeModal},'Close')),
    el('div',{class:'mb'},content));
  bg.appendChild(m);
  bg.addEventListener('mousedown',ev=>{if(ev.target===bg)closeModal();});
  document.body.appendChild(bg);
  modalEl=bg;
}
function saveBlob(name,mime,data){
  const url=URL.createObjectURL(new Blob([data],{type:mime}));
  const a=el('a',{download:name,href:url});
  document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),4000);
}

/* ---------- selection ---------- */
let inspT=0;
function scheduleInspect(now){
  clearTimeout(inspT);
  if(now)doInspect();else inspT=setTimeout(doInspect,30);
}
function doInspect(){
  const e=selI>=0?E[selI]:null;
  reqInsp.render(e);
  respInsp.render(e);
}
function select(i,opt){
  opt=opt||{};
  selI=i;
  renderGrid(true);
  if(opt.scroll!==false&&i>=0&&posOf[i]>=0)ensureVisible(posOf[i]);
  scheduleInspect(opt.now);
  updateStatus();updateCounter();updateHash();updateSessbar();
  if(leftTab==='timeline')drawTimeline();
}
function moveSel(delta){
  if(!view.length)return;
  let p=selI>=0&&posOf[selI]>=0?posOf[selI]:(delta>0?-1:view.length);
  p+=delta;
  while(p>=0&&p<view.length&&view[p]<0)p+=delta>0?1:-1;
  p=Math.max(0,Math.min(view.length-1,p));
  while(p>=0&&p<view.length&&view[p]<0)p+=delta>0?-1:1;
  if(p>=0&&p<view.length)select(view[p]);
}
function updateSessbar(){
  const e=selI>=0?E[selI]:null;
  const info=$('#sbInfo'),mk=$('#sbMark'),nt=$('#sbNote');
  if(!e){info.textContent='No session selected';mk.value='';nt.value='';mk.disabled=nt.disabled=true;return;}
  mk.disabled=nt.disabled=false;
  info.textContent='#'+e.id+'  '+e.method+'  '+(e._status||'0')+'  '+redactText(e.url);
  info.title=e.url;
  const m=marks[e.id]||{};
  mk.value=m.c||'';
  nt.value=m.n||'';
}
function setMark(e,c,n){
  const m=marks[e.id]||{};
  if(c!==undefined)m.c=c;
  if(n!==undefined)m.n=n;
  if(!m.c&&!m.n)delete marks[e.id];else marks[e.id]=m;
  saveMarks();renderGrid(true);
}

/* ---------- search UI glue ---------- */
function updateCounter(){
  const c=$('#cnt');
  if(!S.q||!MATCH){c.textContent='';return;}
  const n=matchPos.length;
  if(!n){c.textContent='No matches';return;}
  const k=selI>=0&&posOf[selI]>=0?matchPos.indexOf(posOf[selI]):-1;
  c.textContent=k>=0?'Match '+(k+1)+' of '+n:n+' matching';
}
function gotoMatch(dir){
  if(!matchPos.length)return;
  const cur=selI>=0&&posOf[selI]>=0?posOf[selI]:(dir>0?-1:view.length);
  let t=-1;
  if(dir>0){for(let k=0;k<matchPos.length;k++)if(matchPos[k]>cur){t=matchPos[k];break;}if(t<0)t=matchPos[0];}
  else{for(let k=matchPos.length-1;k>=0;k--)if(matchPos[k]<cur){t=matchPos[k];break;}if(t<0)t=matchPos[matchPos.length-1];}
  select(view[t],{now:true});
}
function searchDone(user){
  applyView();
  if(user&&matchPos.length&&!(selI>=0&&MATCH&&MATCH[selI]&&posOf[selI]>=0)){
    const cur=selI>=0&&posOf[selI]>=0?posOf[selI]:-1;
    let t=matchPos[0];
    for(let k=0;k<matchPos.length;k++)if(matchPos[k]>=cur){t=matchPos[k];break;}
    select(view[t],{now:true});
  }else{scheduleInspect(true);updateHash();}
}
const qDeb=debounce(()=>runSearch(true),250);
function updateHash(){
  try{
    const parts=[];
    if(selI>=0)parts.push('s='+encodeURIComponent(E[selI].id));
    if(S.q)parts.push('q='+encodeURIComponent(S.q));
    history.replaceState(null,'',parts.length?'#'+parts.join('&'):location.pathname+location.search);
  }catch(err){}
}
function applyHash(){
  const h=location.hash.replace(/^#/,'');
  if(!h)return;
  const p={};
  h.split('&').forEach(x=>{const q=x.indexOf('=');if(q>0){try{p[x.slice(0,q)]=decodeURIComponent(x.slice(q+1));}catch(e){}}});
  if(p.q!=null&&p.q!==S.q){S.q=p.q;$('#q').value=p.q;runSearch(false);}
  if(p.s!=null&&idToIdx.has(p.s)){select(idToIdx.get(p.s),{now:true});}
}

/* ---------- status ---------- */
function updateStatus(){
  let shown=0,errs=0,size=0,t0=Infinity,t1=0;
  for(const i of view){if(i<0)continue;shown++;const e=E[i];if(e._status>=400||e._fail)errs++;size+=e._size;}
  for(const e of E){if(e._t>0){if(e._t<t0)t0=e._t;const en=e._t+e._dur;if(en>t1)t1=en;}}
  const st=$('#status');
  st.textContent='';
  [ 'Showing '+shown+' of '+N,
    selI>=0?'Selected #'+E[selI].id:'No selection',
    errs+' errors (shown)',
    'Total '+fmtBytes(size),
    isFinite(t0)&&t1>t0?'Capture span '+fmtMs(t1-t0):''
  ].forEach(t=>{if(t)st.appendChild(el('span',null,t));});
}

/* ---------- context menu ---------- */
function openCtx(x,y,e){
  const m=$('#ctx');
  m.textContent='';
  const item=(label,fn,dis)=>m.appendChild(el('div',{class:'mi'+(dis?' dis':''),onclick:()=>{m.style.display='none';fn();}},label));
  item('Copy URL',()=>copyText(e.url));
  item('Copy as cURL',()=>copyText(asCurl(e)));
  item('Copy as PowerShell (Invoke-WebRequest)',()=>copyText(asPowerShell(e)));
  item('Copy correlation IDs',()=>copyText(corrText(e)||'(none)'));
  m.appendChild(el('hr'));
  const sw=el('div',{style:'padding:2px 10px'},'Mark: ');
  MARKS.forEach(c=>sw.appendChild(el('span',{class:'sw',title:c,style:'background:'+MARK_RGB[c],onclick:()=>{m.style.display='none';setMark(e,c);if(e._i===selI)updateSessbar();}})));
  sw.appendChild(el('span',{class:'sw',title:'clear',style:'background:transparent',onclick:()=>{m.style.display='none';setMark(e,'');if(e._i===selI)updateSessbar();}},'\u00D7'));
  m.appendChild(sw);
  item('Add / edit note',()=>{select(e._i,{now:true});$('#sbNote').focus();});
  m.appendChild(el('hr'));
  item('Show only this host',()=>{F.text.host=str(e.host);buildFilter();applyView();});
  item('Hide this host',()=>{F.text.host='!'+str(e.host);buildFilter();applyView();});
  m.appendChild(el('hr'));
  const can=selI>=0&&selI!==e._i;
  item(can?'Compare #'+E[selI].id+' with #'+e.id+'...':'Compare with... (select another session first)',()=>openCompare(selI,e._i),!can);
  m.style.display='block';
  m.style.left=Math.min(x,window.innerWidth-m.offsetWidth-4)+'px';
  m.style.top=Math.min(y,window.innerHeight-m.offsetHeight-4)+'px';
}


/* ---------- inspector helpers ---------- */
const CAP=2000000;
const NOCAP='Body not captured by the browser (content stripped or not available)';
function appendHL(parent,text,re,limit){
  text=String(text);
  if(!re){parent.appendChild(document.createTextNode(text));return 0;}
  re.lastIndex=0;
  let last=0,n=0,m;
  const lim=limit||3000;
  while((m=re.exec(text))!==null){
    if(m[0]===''){re.lastIndex++;continue;}
    if(m.index>last)parent.appendChild(document.createTextNode(text.slice(last,m.index)));
    parent.appendChild(el('mark',null,m[0]));
    last=m.index+m[0].length;n++;
    if(n>=lim)break;
  }
  if(last<text.length)parent.appendChild(document.createTextNode(text.slice(last)));
  return n;
}
function countMatches(text,re){
  if(!re||!text)return 0;
  re.lastIndex=0;
  let n=0,m;
  while((m=re.exec(text))!==null){
    if(m[0]===''){re.lastIndex++;continue;}
    if(++n>=999)break;
  }
  return n;
}
const note=t=>el('div',{class:'note'},t);
const empty=t=>el('div',{class:'empty'},t);
function sec(t){return el('div',{class:'sec'},t);}
function kvTable(rows,re){
  const t=el('table',{class:'t'});
  rows.forEach(r=>{
    const td=el('td',{class:'v'});
    appendHL(td,str(r[1]),re);
    t.appendChild(el('tr',null,el('td',{class:'k'},r[0]),td));
  });
  return t;
}
function gridTable(head,rows,re){
  const t=el('table',{class:'t'});
  t.appendChild(el('tr',null,head.map(h=>el('th',null,h))));
  rows.forEach(r=>{
    t.appendChild(el('tr',null,r.map(c=>{
      const td=el('td',{class:'v'});
      if(c instanceof Node)td.appendChild(c);else appendHL(td,str(c),re);
      return td;
    })));
  });
  return t;
}
function pathQ(e){
  try{const u=new URL(e.url);return u.pathname+u.search;}catch(err){return str(e.path)||e.url;}
}
function noBodyExpected(e){
  const s=e._status;
  return s===204||s===304||(s>=100&&s<200)||(s>=300&&s<400)||String(e.method).toUpperCase()==='HEAD';
}
function getBody(e,kind){return (kind==='req'?e.reqBody:e.respBody)||null;}
function isBin(b){return !!b&&(b.format==='binary'||(str(b.decoded)===''&&!!b.b64));}
function bodyView(e,kind,mode){
  const b=getBody(e,kind);
  const out={b:b,text:'',msg:'',note:'',bin:false};
  if(b&&b.truncated)out.note='Body truncated by the report generator'+(b.originalSize!=null?' (original size '+fmtBytes(b.originalSize)+')':'')+'.';
  if(!b){
    if(kind==='req')out.msg='No request body.';
    else if(e._fail&&!e._status)out.msg='No response received (request failed'+(e.error?': '+e.error:'')+').';
    else out.msg=noBodyExpected(e)?'No response body.':NOCAP;
    return out;
  }
  let t=mode==='raw'?str(b.raw):(str(b.decoded)!==''?str(b.decoded):(isBin(b)?'':str(b.raw)));
  if(t!==''){out.text=redactText(t);return out;}
  if(isBin(b)){out.msg='Binary content ('+fmtBytes(b.size||0)+'). See the Hex tab'+(kind==='resp'?' or Preview':'')+'.';out.bin=true;return out;}
  const size=num(b.size);
  if(kind==='req')out.msg=size>0?NOCAP:'No request body.';
  else if(e._fail&&!e._status)out.msg='No response received (request failed'+(e.error?': '+e.error:'')+').';
  else out.msg=(size>0||!noBodyExpected(e))?NOCAP:'Empty response body.';
  return out;
}
function textBox(text,re){
  const w=el('div');
  let t=text;
  if(t.length>CAP){w.appendChild(note('Showing the first '+CAP.toLocaleString()+' of '+t.length.toLocaleString()+' characters. Use Download for the complete body.'));t=t.slice(0,CAP);}
  const pre=el('pre');
  appendHL(pre,t,re);
  w.appendChild(pre);
  return w;
}
function formatXml(s){
  const toks=s.match(/<!\[CDATA\[[\s\S]*?\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<![^>]*>|<[^>]+>|[^<]+/g)||[];
  const lines=[];
  let d=0;
  for(let i=0;i<toks.length;i++){
    let t=toks[i];
    if(t[0]!=='<'){t=t.trim();if(t)lines.push('  '.repeat(d)+t);continue;}
    if(/^<\//.test(t)){d=Math.max(0,d-1);lines.push('  '.repeat(d)+t);}
    else if(/^<[^!?]/.test(t)&&!/\/>$/.test(t)){
      const n1=toks[i+1],n2=toks[i+2];
      if(n1&&n1[0]!=='<'&&n2&&/^<\//.test(n2)){lines.push('  '.repeat(d)+t+n1.trim()+n2);i+=2;}
      else{lines.push('  '.repeat(d)+t);d++;}
    }else lines.push('  '.repeat(d)+t);
  }
  return lines.join('\n');
}
const looksXml=s=>/^\s*(<\?xml|<[A-Za-z!])/.test(s);

/* ---------- JSON tree ---------- */
function treeNode(parent,key,val,depth,re,st){
  st.n++;
  const line=el('div',{class:'n'});
  const keyEl=()=>{const k=el('span',{class:'key'});appendHL(k,String(key),re);return k;};
  const isObj=val!==null&&typeof val==='object';
  if(!isObj){
    if(key!==null){line.appendChild(keyEl());line.appendChild(document.createTextNode(': '));}
    const t=typeof val;
    const v=el('span',{class:t==='string'?'str':t==='number'?'numv':t==='boolean'?'bool':'nul'});
    appendHL(v,t==='string'?JSON.stringify(val):String(val),re);
    line.appendChild(v);
    parent.appendChild(line);
    return;
  }
  const arr=Array.isArray(val),keys=Object.keys(val);
  const tg=el('span',{class:'tg'},'\u25B6');
  line.appendChild(tg);
  if(key!==null){line.appendChild(keyEl());line.appendChild(document.createTextNode(': '));}
  line.appendChild(el('span',{class:'nul'},(arr?'[':'{')+keys.length+(arr?']':'}')));
  const cont=el('div',{style:'display:none'});
  let built=false;
  const PAGE=300;
  const buildFrom=from=>{
    const to=Math.min(keys.length,from+PAGE);
    for(let i=from;i<to;i++)treeNode(cont,arr?i:keys[i],val[keys[i]],depth+1,re,st);
    if(to<keys.length){
      const more=el('div',{class:'n more'},'\u2026 '+(keys.length-to)+' more');
      more.addEventListener('click',()=>{more.remove();buildFrom(to);});
      cont.appendChild(more);
    }
  };
  const setOpen=o=>{
    if(o&&!built){built=true;buildFrom(0);}
    cont.style.display=o?'':'none';
    tg.textContent=o?'\u25BC':'\u25B6';
  };
  tg.addEventListener('click',()=>setOpen(cont.style.display==='none'));
  parent.appendChild(line);
  parent.appendChild(cont);
  if(keys.length&&(depth<2||(re&&st.n<4000)))setOpen(true);
}
function buildTree(val,re){
  const root=el('div',{class:'tree'});
  treeNode(root,null,val,0,re,{n:0});
  return root;
}

/* ---------- hex ---------- */
function b64ToBytes(s){
  const bin=atob(s);
  const u=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);
  return u;
}
function bodyBytes(e,kind,mode){
  const b=getBody(e,kind);
  if(!b)return null;
  if(b.b64&&/^[A-Za-z0-9+\/=\s]+$/.test(b.b64)){try{return b64ToBytes(b.b64.replace(/\s/g,''));}catch(err){}}
  const t=mode==='raw'?str(b.raw):(str(b.decoded)!==''?str(b.decoded):str(b.raw));
  return t===''?null:new TextEncoder().encode(t);
}
function hexDump(u,cap){
  const n=Math.min(u.length,cap),lines=[];
  for(let o=0;o<n;o+=16){
    let h='',a='';
    for(let i=0;i<16;i++){
      if(o+i<n){const v=u[o+i];h+=(v<16?'0':'')+v.toString(16).toUpperCase()+' ';a+=(v>=32&&v<127)?String.fromCharCode(v):'.';}
      else h+='   ';
      if(i===7)h+=' ';
    }
    lines.push(('00000000'+o.toString(16).toUpperCase()).slice(-8)+'  '+h+' '+a);
  }
  return lines.join('\n');
}

/* ---------- header grouping ---------- */
const GROUPS=['Cache','Client','Cookies','Security','Transport','Other'];
function hdrGroup(n){
  n=n.toLowerCase();
  if(/^(cache-control|pragma|expires|etag|last-modified|age|vary|if-match|if-none-match|if-modified-since|if-unmodified-since|if-range|clear-site-data)$/.test(n))return 'Cache';
  if(/^(cookie|set-cookie|cookie2|set-cookie2)$/.test(n))return 'Cookies';
  if(/^(authorization|proxy-authorization|www-authenticate|proxy-authenticate|strict-transport-security|content-security-policy(-report-only)?|x-frame-options|x-content-type-options|x-xss-protection|access-control-[\w-]+|sec-fetch-[\w-]+|cross-origin-[\w-]+|permissions-policy|referrer-policy|expect-ct|public-key-pins|x-permitted-cross-domain-policies)$/.test(n))return 'Security';
  if(/^(connection|content-length|content-type|content-encoding|content-language|content-disposition|transfer-encoding|keep-alive|upgrade|te|trailer|date|server|location|via|alt-svc|range|content-range|accept-ranges|:.*)$/.test(n))return 'Transport';
  if(/^(accept(-[\w-]+)?|user-agent|referer|origin|host|sec-ch-[\w-]+|dnt|upgrade-insecure-requests|from|x-requested-with|priority|purpose)$/.test(n))return 'Client';
  return 'Other';
}

/* ---------- tab renderers ---------- */
function rawRequestText(e,mode){
  const lines=[e.method+' '+pathQ(e)+' '+(str(e.httpVersion)||'HTTP/1.1')];
  e.reqHeaders.forEach(h=>lines.push(str(h.name)+': '+redactHeader(str(h.name),str(h.value))));
  const bv=bodyView(e,'req',mode);
  let s=lines.join('\r\n')+'\r\n\r\n';
  if(bv.text)s+=bv.text;else if(bv.bin)s+='[binary body, '+fmtBytes(bv.b&&bv.b.size)+']';
  return s;
}
function rawResponseText(e,mode){
  const lines=[(str(e.httpVersion)||'HTTP/1.1')+' '+(e._status||0)+' '+str(e.statusText)];
  e.respHeaders.forEach(h=>lines.push(str(h.name)+': '+redactHeader(str(h.name),str(h.value))));
  const bv=bodyView(e,'resp',mode);
  let s=lines.join('\r\n')+'\r\n\r\n';
  if(bv.text)s+=bv.text;else if(bv.bin)s+='[binary body, '+fmtBytes(bv.b&&bv.b.size)+']';
  return s;
}
function tHeaders(e,ctx){
  const kind=ctx.kind,re=hlRe(kind==='req'?'reqh':'resh'),reU=hlRe('url');
  const root=el('div');
  const list=kind==='req'?e.reqHeaders:e.respHeaders;
  let copy='';
  const gen=[];
  if(kind==='req'){
    gen.push(['Request',e.method+' '+redactText(pathQ(e))+' '+str(e.httpVersion)]);
    gen.push(['URL',redactText(e.url)]);
  }else{
    gen.push(['Status',str(e.httpVersion)+' '+(e._status||0)+' '+str(e.statusText)]);
    if(e.error)gen.push(['Error',e.error]);
    if(e._ct)gen.push(['Content-Type',e._ct]);
    gen.push(['Body size',fmtBytes(e._size)+(e._xfer>=0?' (transfer '+fmtBytes(e._xfer)+')':'')]);
    if(e.redirectURL)gen.push(['Redirect to',redactText(e.redirectURL)]);
  }
  if(e.serverIp)gen.push(['Server IP',e.serverIp]);
  if(e.connection)gen.push(['Connection',e.connection]);
  if(e.resourceType)gen.push(['Resource type',e.resourceType]);
  if(kind==='req'&&e._initiator!=null)gen.push(['Initiator',str(e._initiator)]);
  if(kind==='req'&&e._priority!=null)gen.push(['Priority',str(e._priority)]);
  if(kind==='resp'&&e.fromCache)gen.push(['From cache','yes']);
  root.appendChild(sec('General'));
  root.appendChild(kvTable(gen,reU));
  copy+=gen.map(r=>r[0]+': '+r[1]).join('\n')+'\n';
  if(!list.length){root.appendChild(empty('No headers captured.'));ctx.copy=copy;return root;}
  const by={};
  GROUPS.forEach(g=>by[g]=[]);
  list.forEach(h=>by[hdrGroup(str(h&&h.name))].push([str(h&&h.name),redactHeader(str(h&&h.name),str(h&&h.value))]));
  GROUPS.forEach(g=>{
    if(!by[g].length)return;
    by[g].sort((a,b)=>a[0].toLowerCase()<b[0].toLowerCase()?-1:1);
    root.appendChild(sec(g));
    root.appendChild(kvTable(by[g],re));
    copy+='\n['+g+']\n'+by[g].map(r=>r[0]+': '+r[1]).join('\n')+'\n';
  });
  if(kind==='resp'&&e.correlation&&Object.keys(e.correlation).length){
    root.appendChild(sec('Correlation IDs'));
    root.appendChild(kvTable(Object.keys(e.correlation).map(k=>[k,e.correlation[k]]),re));
    root.appendChild(el('button',{style:'margin-top:4px',onclick:()=>copyText(corrText(e))},'Copy correlation IDs'));
  }
  ctx.copy=copy;
  return root;
}
function tText(e,ctx){
  const bv=bodyView(e,ctx.kind,ctx.mode);
  const root=el('div');
  if(bv.note)root.appendChild(note(bv.note));
  if(bv.msg){root.appendChild(empty(bv.msg));return root;}
  ctx.copy=bv.text;
  root.appendChild(textBox(bv.text,hlRe(ctx.kind==='req'?'reqb':'resb')));
  return root;
}
function tJson(e,ctx){
  const bv=bodyView(e,ctx.kind,ctx.mode);
  const root=el('div');
  if(bv.note)root.appendChild(note(bv.note));
  if(bv.msg){root.appendChild(empty(bv.msg));return root;}
  const re=hlRe(ctx.kind==='req'?'reqb':'resb');
  let obj;
  try{obj=JSON.parse(bv.text);}
  catch(err){
    root.appendChild(note('This body is not valid JSON ('+err.message+'). Showing it as text.'));
    ctx.copy=bv.text;root.appendChild(textBox(bv.text,re));return root;
  }
  const pretty=JSON.stringify(obj,null,2);
  ctx.copy=pretty;
  const bar=el('div',{style:'margin-bottom:6px;font-family:Segoe UI,sans-serif'});
  ['tree','pretty'].forEach(v=>bar.appendChild(el('button',{class:UI.jsonView===v?'on':'',style:'margin-right:3px',onclick:()=>{UI.jsonView=v;saveUI();ctx.rerender();}},v==='tree'?'Tree':'Pretty')));
  root.appendChild(bar);
  if(UI.jsonView==='tree'&&obj!==null&&typeof obj==='object')root.appendChild(buildTree(obj,re));
  else root.appendChild(textBox(pretty,re));
  return root;
}
function tXml(e,ctx){
  const bv=bodyView(e,ctx.kind,ctx.mode);
  const root=el('div');
  if(bv.note)root.appendChild(note(bv.note));
  if(bv.msg){root.appendChild(empty(bv.msg));return root;}
  if(!looksXml(bv.text)||bv.text.length>CAP){root.appendChild(empty('This body does not look like XML.'));return root;}
  const f=formatXml(bv.text);
  ctx.copy=f;
  root.appendChild(textBox(f,hlRe(ctx.kind==='req'?'reqb':'resb')));
  return root;
}
function tWebForms(e,ctx){
  const root=el('div');
  const reU=hlRe('url'),reB=hlRe('reqb');
  let any=false;
  const q=Array.isArray(e.queryParams)?e.queryParams:[];
  let copy='';
  if(q.length){
    any=true;root.appendChild(sec('Query string'));
    root.appendChild(gridTable(['Name','Value'],q.map(p=>[str(p.name),redactVal(str(p.name),str(p.value))]),reU));
    copy+=q.map(p=>str(p.name)+'='+str(p.value)).join('\n')+'\n';
  }
  const rb=e.reqBody||{};
  let params=Array.isArray(rb.params)?rb.params:[];
  if(!params.length&&rb.format==='form'){
    try{params=Array.from(new URLSearchParams(str(rb.decoded)||str(rb.raw)).entries()).map(x=>({name:x[0],value:x[1]}));}catch(err){}
  }
  if(params.length){
    any=true;root.appendChild(sec('Form body (application/x-www-form-urlencoded)'));
    root.appendChild(gridTable(['Name','Value'],params.map(p=>[str(p.name),redactVal(str(p.name),str(p.value))]),reB));
    copy+=params.map(p=>str(p.name)+'='+str(p.value)).join('\n')+'\n';
  }
  if(Array.isArray(rb.parts)&&rb.parts.length){
    any=true;root.appendChild(sec('Multipart parts'));
    root.appendChild(gridTable(['Name','File name','Content-Type','Size','Content'],rb.parts.map(p=>{
      const tx=str(p&&p.text);
      return [str(p&&p.name),str(p&&p.filename),str(p&&p.contentType),p&&p.size!=null?fmtBytes(p.size):'',tx?redactText(tx.length>600?tx.slice(0,600)+'\u2026':tx):(p&&p.filename?'(file content not shown)':'')];
    }),reB));
  }
  if(!any)root.appendChild(empty('No query string, form or multipart data.'));
  ctx.copy=copy;
  return root;
}
function parseCookieHeader(v){
  return str(v).split(/;\s*/).filter(Boolean).map(p=>{const i=p.indexOf('=');return i<0?{name:p,value:''}:{name:p.slice(0,i),value:p.slice(i+1)};});
}
function tCookies(e,ctx){
  const root=el('div');
  const kind=ctx.kind,re=hlRe(kind==='req'?'reqh':'resh');
  let copy='';
  if(kind==='req'){
    let c=Array.isArray(e.reqCookies)?e.reqCookies:[];
    if(!c.length)c=parseCookieHeader(hget(e.reqHeaders,'cookie'));
    if(!c.length){root.appendChild(empty('No request cookies.'));return root;}
    root.appendChild(gridTable(['Name','Value'],c.map(x=>[str(x.name),UI.redact?mask(x.value):str(x.value)]),re));
    copy=c.map(x=>str(x.name)+'='+(UI.redact?mask(x.value):str(x.value))).join('\n');
  }else{
    const c=Array.isArray(e.respCookies)?e.respCookies:[];
    if(!c.length){
      const sc=e.respHeaders.filter(h=>/^set-cookie$/i.test(str(h.name)));
      if(!sc.length){root.appendChild(empty('No Set-Cookie headers.'));return root;}
      root.appendChild(gridTable(['Set-Cookie'],sc.map(h=>[redactHeader('set-cookie',str(h.value))]),re));
      copy=sc.map(h=>redactHeader('set-cookie',str(h.value))).join('\n');
    }else{
      root.appendChild(gridTable(['Name','Value','Domain','Path','Expires','Secure','HttpOnly','SameSite'],c.map(x=>{
        const ss=str(x.sameSite);
        const bad=/^none$/i.test(ss)&&!x.secure;
        return [str(x.name),UI.redact?mask(x.value):str(x.value),str(x.domain),str(x.path),str(x.expires),x.secure?'Secure':'',x.httpOnly?'HttpOnly':'',bad?ss+' \u26A0 without Secure':ss];
      }),re));
      copy=c.map(x=>str(x.name)+'='+(UI.redact?mask(x.value):str(x.value))).join('\n');
    }
  }
  ctx.copy=copy;
  return root;
}
const PROM=['aud','iss','tid','oid','upn','scp','roles','appid','sub','azp','appidacr','name','preferred_username','unique_name','email','ver','amr','nonce'];
function claimStr(v){return Array.isArray(v)?v.map(claimStr).join(', '):(v!==null&&typeof v==='object'?JSON.stringify(v):str(v));}
function jwtCard(j,e,re){
  const p=j&&j.payload&&typeof j.payload==='object'?j.payload:{};
  const exp=p.exp!=null?num(p.exp):null;
  const expired=j.expired!=null?!!j.expired:(exp!=null?exp*1000<(e._t||Date.now()):false);
  const card=el('div',{class:'jcard'});
  const tok=str(j.token);
  card.appendChild(el('div',{class:'jh'},
    el('b',null,'JWT'),el('span',null,str(j.where)),
    exp!=null||j.expired!=null?el('span',{class:'badge '+(expired?'bad':'good')},expired?'EXPIRED':'not expired'):null));
  const b=el('div',{class:'jb'});
  const tk=el('div',{class:'mono',style:'word-break:break-all;margin-bottom:5px;color:var(--mut)'});
  appendHL(tk,UI.redact?mask(tok):tok,re);
  b.appendChild(tk);
  const rows=[];
  PROM.forEach(k=>{if(p[k]!==undefined)rows.push([k,claimStr(p[k])]);});
  [['exp','Expires'],['iat','Issued at'],['nbf','Not before']].forEach(x=>{
    if(p[x[0]]!=null&&isFinite(Number(p[x[0]])))rows.push([x[0]+' ('+x[1]+')',fmtEpoch(p[x[0]])+'  ['+p[x[0]]+']']);
  });
  if(exp==null&&j.expiresAt)rows.push(['Expires',str(j.expiresAt)]);
  if(rows.length)b.appendChild(kvTable(rows,re));
  b.appendChild(sec('Header'));
  b.appendChild(el('pre',null,JSON.stringify(j.header||{},null,2)));
  b.appendChild(sec('Payload'));
  const pre=el('pre');appendHL(pre,JSON.stringify(p,null,2),re);b.appendChild(pre);
  b.appendChild(el('div',{class:'empty',style:'padding:4px 0'},'Signature is not decoded or validated.'));
  card.appendChild(b);
  return card;
}
const OAUTH_ORDER=['client_id','response_type','scope','grant_type','redirect_uri','prompt','login_hint','state','nonce','response_mode','resource','audience','error','error_description'];
function tAuth(e,ctx){
  const kind=ctx.kind,re=hlRe('auth');
  const root=el('div');
  const a=e.auth&&typeof e.auth==='object'?e.auth:{};
  const jw=(Array.isArray(a.jwt)?a.jwt:[]).filter(j=>{const isResp=/resp/i.test(str(j&&j.where));return kind==='resp'?isResp:!isResp;});
  let copy='';
  if(kind==='req'&&a.oauthParams&&Object.keys(a.oauthParams).length){
    root.appendChild(sec('OAuth / OIDC parameters'));
    const ks=Object.keys(a.oauthParams).sort((x,y)=>{const i=OAUTH_ORDER.indexOf(x),j=OAUTH_ORDER.indexOf(y);return (i<0?99:i)-(j<0?99:j);});
    root.appendChild(kvTable(ks.map(k=>[k,redactVal(k,claimStr(a.oauthParams[k]))]),re));
    copy+=ks.map(k=>k+'='+redactVal(k,claimStr(a.oauthParams[k]))).join('\n')+'\n';
  }
  if(jw.length){
    root.appendChild(sec('Decoded JWT tokens ('+jw.length+')'));
    jw.forEach(j=>{root.appendChild(jwtCard(j,e,re));copy+=JSON.stringify(j.payload,null,2)+'\n';});
  }
  if(!root.firstChild)root.appendChild(empty(kind==='req'?'No JWT or OAuth parameters found in this request.':'No tokens found in this response.'));
  ctx.copy=copy;
  return root;
}
function tSaml(e,ctx){
  const re=hlRe('auth');
  const root=el('div');
  const list=e.auth&&Array.isArray(e.auth.saml)?e.auth.saml:[];
  if(!list.length){root.appendChild(empty('No SAML message found in this request.'));return root;}
  let copy='';
  list.forEach(s=>{
    const card=el('div',{class:'jcard'});
    card.appendChild(el('div',{class:'jh'},el('b',null,'SAML'),el('span',null,str(s.kind))));
    const b=el('div',{class:'jb'});
    const rows=[['Issuer',s.issuer],['NameID',s.nameId],['Audience',s.audience],['NotBefore',s.notBefore],['NotOnOrAfter',s.notOnOrAfter],['StatusCode',s.statusCode]].filter(r=>r[1]);
    if(rows.length)b.appendChild(kvTable(rows,re));
    if(Array.isArray(s.attributes)&&s.attributes.length){
      b.appendChild(sec('Attributes'));
      b.appendChild(gridTable(['Name','Value'],s.attributes.map(x=>[str(x.name),redactVal(str(x.name),str(x.value))]),re));
    }
    const xml=str(s.xml);
    if(xml){
      b.appendChild(sec('XML'));
      const f=xml.length<CAP&&looksXml(xml)?formatXml(xml):xml;
      const pre=el('pre');appendHL(pre,UI.redact?redactText(f):f,re);b.appendChild(pre);
      copy+=f+'\n';
    }
    card.appendChild(b);root.appendChild(card);
  });
  ctx.copy=copy;
  return root;
}
function tRaw(e,ctx){
  const t=ctx.kind==='req'?rawRequestText(e,ctx.mode):rawResponseText(e,ctx.mode);
  ctx.copy=t;
  const root=el('div');
  const bv=bodyView(e,ctx.kind,ctx.mode);
  if(bv.note)root.appendChild(note(bv.note));
  if(bv.msg&&!bv.bin)root.appendChild(note(bv.msg));
  root.appendChild(textBox(t,hlRe(ctx.kind==='req'?'reqb':'resb')||hlRe(ctx.kind==='req'?'reqh':'resh')));
  return root;
}
function tHex(e,ctx){
  let u=null;
  try{u=bodyBytes(e,ctx.kind,ctx.mode);}catch(err){}
  if(!u||!u.length)return empty(bodyView(e,ctx.kind,ctx.mode).msg||'No body data.');
  const root=el('div');
  const cap=262144;
  root.appendChild(note(u.length.toLocaleString()+' bytes'+(u.length>cap?'. Showing the first '+cap.toLocaleString()+' bytes; use Download for the full body.':'.')));
  const t=hexDump(u,cap);
  ctx.copy=t;
  root.appendChild(el('pre',null,t));
  return root;
}
function imgDataUri(e){
  const b=e.respBody||{};
  let mime=str(e.mimeType).split(';')[0].trim().toLowerCase();
  if(!/^image\/[\w.+-]+$/.test(mime))mime='image/png';
  let b64=str(b.b64);
  if(!b64&&b.encoding==='base64'&&isBin(b)||(!b64&&b.encoding==='base64'&&/^image\//.test(mime)))b64=str(b.raw);
  if(b64&&/^[A-Za-z0-9+\/=\s]+$/.test(b64))return 'data:'+mime+';base64,'+b64.replace(/\s/g,'');
  if(mime==='image/svg+xml'&&str(b.decoded))return 'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(str(b.decoded));
  return '';
}
function tPreview(e,ctx){
  const root=el('div');
  const mt=str(e.mimeType).toLowerCase();
  if(e.resourceType==='image'||/^image\//.test(mt)){
    const uri=imgDataUri(e);
    if(uri){
      root.appendChild(el('img',{src:uri,alt:'Response image preview',style:'max-width:100%;background:repeating-conic-gradient(#ddd 0 25%,#fff 0 50%) 0 0/16px 16px;border:1px solid var(--bd)'}));
      return root;
    }
    return empty(bodyView(e,'resp','decoded').msg||'No image data available.');
  }
  const b=e.respBody||{};
  if((b.format==='html'||/html/.test(mt))&&str(b.decoded)!==''){
    root.appendChild(note('Sandboxed preview: scripts, forms and external resources are disabled.'));
    const f=el('iframe',{sandbox:'',title:'HTML preview',style:'width:100%;height:calc(100% - 50px);min-height:240px;border:1px solid var(--bd);background:#fff'});
    f.srcdoc=redactText(str(b.decoded));
    root.appendChild(f);
    return root;
  }
  root.appendChild(empty('No visual preview for this content type. Use the TextView, JSON or Hex tabs.'));
  return root;
}
const PH=[['blocked','Blocked / queued','#9e9e9e'],['dns','DNS','#1e88e5'],['connect','Connect','#fb8c00'],['ssl','SSL/TLS','#8e24aa'],['send','Send','#43a047'],['wait','Wait (TTFB)','#e53935'],['receive','Receive','#00acc1']];
function phaseVals(e){
  const t=e.timings||{};
  const v={};
  PH.forEach(p=>{const x=Number(t[p[0]]);v[p[0]]=isFinite(x)&&x>0?x:0;});
  const raw=v.connect;
  if(v.ssl>0&&v.connect>=v.ssl)v.connect=v.connect-v.ssl;
  return {v,raw};
}
function tTiming(e,ctx){
  const root=el('div',{style:'font-family:Segoe UI,Tahoma,sans-serif'});
  const t=e.timings||{};
  const pv=phaseVals(e).v;
  const sum=PH.reduce((a,p)=>a+pv[p[0]],0);
  if(sum<=0&&!e._dur){root.appendChild(empty('No timing information available.'));return root;}
  const tw=el('div',{class:'tw'});
  PH.forEach(p=>{if(pv[p[0]]>0)tw.appendChild(el('div',{style:'width:'+(pv[p[0]]/sum*100)+'%;background:'+p[2],title:p[1]+': '+fmtMs(pv[p[0]])}));});
  root.appendChild(tw);
  const lg=el('div',{class:'wf'});
  PH.forEach(p=>lg.appendChild(el('span',null,el('i',{style:'background:'+p[2]}),p[1])));
  root.appendChild(lg);
  const rows=PH.map(p=>{const raw=Number(t[p[0]]);return [p[1],isFinite(raw)&&raw>=0&&t[p[0]]!=null?fmtMs(raw):'n/a'];});
  rows.push(['Total',fmtMs(e._dur)]);
  rows.push(['Started',fmtTs(e._t,UI.tz==='UTC'?'UTC':'Local')+(UI.tz==='UTC'?' UTC':'')]);
  root.appendChild(el('div',{style:'height:8px'}));
  root.appendChild(kvTable(rows,null));
  root.appendChild(el('div',{class:'empty',style:'padding:4px 0'},'SSL time is part of Connect in the HAR format; the bar shows Connect without it.'));
  ctx.copy=rows.map(r=>r[0]+': '+r[1]).join('\n');
  return root;
}
/* redirects */
let RG=null;
const normUrl=u=>str(u).split('#')[0];
function redirectTarget(e){
  if(!(e._status>=300&&e._status<400))return '';
  const loc=str(e.redirectURL)||hget(e.respHeaders,'location');
  if(!loc)return '';
  try{return new URL(loc,e.url).href;}catch(err){return loc;}
}
function buildRG(){
  const by=new Map();
  E.forEach(e=>{const k=normUrl(e.url);if(!by.has(k))by.set(k,[]);by.get(k).push(e._i);});
  const nxt=new Int32Array(N).fill(-1),prv=new Int32Array(N).fill(-1);
  E.forEach(e=>{
    const t=redirectTarget(e);
    if(!t)return;
    const l=by.get(normUrl(t));
    if(!l)return;
    for(const j of l){if(j>e._i){nxt[e._i]=j;if(prv[j]<0)prv[j]=e._i;break;}}
  });
  RG={nxt,prv};
}
function tRedirects(e,ctx){
  if(!RG)buildRG();
  const root=el('div',{class:'chain',style:'font-family:Segoe UI,sans-serif'});
  const chain=[e._i];
  const seen=new Set(chain);
  let c=e._i;
  while(RG.prv[c]>=0&&!seen.has(RG.prv[c])){c=RG.prv[c];seen.add(c);chain.unshift(c);}
  c=e._i;
  while(RG.nxt[c]>=0&&!seen.has(RG.nxt[c])){c=RG.nxt[c];seen.add(c);chain.push(c);}
  const last=E[chain[chain.length-1]];
  const lastT=redirectTarget(last);
  if(chain.length===1&&!lastT){root.appendChild(empty('This session is not part of a redirect chain.'));return root;}
  const urls=chain.map(i=>normUrl(E[i].url));
  if(new Set(urls).size<urls.length||(RG.nxt[last._i]>=0))root.appendChild(note('Possible redirect loop: the same URL appears more than once in the chain.'));
  let copy='';
  chain.forEach((i,k)=>{
    const x=E[i];
    if(k)root.appendChild(el('div',{class:'arrow'},'\u2193'));
    const hop=el('div',{class:'hop'+(i===e._i?' cur':'')},el('b',null,'#'+x.id+'  '+x.method+'  '+(x._status||0)+'  '),redactText(x.url));
    hop.addEventListener('click',()=>{if(i!==selI)select(i,{now:true});});
    root.appendChild(hop);
    copy+=(k+1)+'. #'+x.id+' '+x.method+' '+x._status+' '+x.url+'\n';
  });
  if(lastT&&RG.nxt[last._i]<0){
    root.appendChild(el('div',{class:'arrow'},'\u2193'));
    root.appendChild(el('div',{class:'hop',style:'cursor:default'},'\u2192 '+redactText(lastT)+'  (target not present in this capture)'));
    copy+='-> '+lastT+'\n';
  }
  ctx.copy=copy;
  return root;
}
/* caching */
function tCaching(e,ctx){
  const root=el('div',{style:'font-family:Segoe UI,sans-serif'});
  const h=n=>hget(e.respHeaders,n);
  const rows=[['Cache-Control',h('cache-control')],['ETag',h('etag')],['Last-Modified',h('last-modified')],['Expires',h('expires')],['Age',h('age')],['Pragma',h('pragma')],['Vary',h('vary')],['Date',h('date')],
    ['Served from cache',e.fromCache?'yes':'no'],['Status 304 (validated)',e._status===304?'yes':'no'],
    ['Request Cache-Control',hget(e.reqHeaders,'cache-control')],['If-None-Match',hget(e.reqHeaders,'if-none-match')],['If-Modified-Since',hget(e.reqHeaders,'if-modified-since')]].filter(r=>r[1]!=='');
  root.appendChild(kvTable(rows,null));
  const cc=h('cache-control').toLowerCase();
  const f=[];
  const ma=/(?:^|[\s,])s?-?max-age=(\d+)/.exec(cc);
  if(/no-store/.test(cc))f.push('no-store: the response must not be stored by any cache.');
  if(/no-cache/.test(cc))f.push('no-cache: caches must revalidate with the server before reuse.');
  if(/\bprivate\b/.test(cc))f.push('private: only the browser cache may store this response.');
  if(/\bpublic\b/.test(cc))f.push('public: shared caches (CDN, proxy) may store this response.');
  if(ma)f.push('max-age='+ma[1]+' s: fresh for '+fmtMs(ma[1]*1000)+' from the response time.');
  else if(h('expires')&&!/no-cache|no-store/.test(cc))f.push('Freshness is derived from the Expires header.');
  if(!cc&&!h('expires')&&(h('etag')||h('last-modified')))f.push('No explicit freshness; the browser may apply heuristic caching based on Last-Modified.');
  if(!cc&&!h('expires')&&!h('etag')&&!h('last-modified')&&e._status===200)f.push('No cache headers: the response is effectively not cacheable (or heuristic only).');
  if(e._status===304)f.push('304 Not Modified: the cached copy was validated with the server and reused.');
  if(e.fromCache)f.push('The browser served this response from its cache without contacting the server.');
  if(h('etag')&&!hget(e.reqHeaders,'if-none-match')&&e._status===200)f.push('A validator (ETag) is available for conditional requests.');
  root.appendChild(sec('Analysis'));
  const ul=el('ul',{style:'margin:4px 0;padding-left:20px'});
  (f.length?f:['No caching information available.']).forEach(x=>ul.appendChild(el('li',null,x)));
  root.appendChild(ul);
  ctx.copy=rows.map(r=>r[0]+': '+r[1]).join('\n')+'\n\n'+f.join('\n');
  return root;
}
function tWebSocket(e,ctx){
  const m=Array.isArray(e.wsMessages)?e.wsMessages:[];
  if(!m.length)return empty('No WebSocket frames.');
  const re=hlRe('resb');
  const rows=m.map(x=>{
    let d=str(x&&x.data);
    try{const j=JSON.parse(d);if(j!==null&&typeof j==='object')d=JSON.stringify(j,null,2);}catch(err){}
    let tm=num(x&&x.time);
    if(tm>0&&tm<1e11)tm*=1000;
    const ty=str(x&&x.type);
    return [/send/i.test(ty)?'\u2B06 send':/receive/i.test(ty)?'\u2B07 receive':ty,tm?fmtTs(tm,UI.tz==='UTC'?'UTC':'Local'):'',str(x&&x.opcode),redactText(d)];
  });
  ctx.copy=rows.map(r=>r.join('\t')).join('\n');
  return gridTable(['Direction','Time','Opcode','Data'],rows,re);
}
function tInsights(e,ctx){
  const l=Array.isArray(e.insights)?e.insights:[];
  if(!l.length)return empty('No insights for this session.');
  const t=el('table',{class:'t',style:'font-family:Segoe UI,sans-serif'});
  l.forEach(x=>{
    const sv=str(x&&x.severity)||'info';
    t.appendChild(el('tr',null,el('td',{style:'width:1%'},el('span',{class:'ins-'+sv},(INS_ICON[sv]||'')+' '+sv)),el('td',null,str(x&&x.message))));
  });
  ctx.copy=l.map(x=>str(x.severity)+': '+str(x.message)).join('\n');
  return t;
}

const REQ_TABS=[
 {id:'headers',l:'Headers',r:tHeaders,txt:(e)=>hdrText(e.reqHeaders),sc:'reqh'},
 {id:'text',l:'TextView',r:tText,body:1},
 {id:'forms',l:'WebForms',r:tWebForms,txt:(e)=>(Array.isArray(e.queryParams)?e.queryParams:[]).map(p=>str(p.name)+'='+str(p.value)).join('\n')+'\n'+(e.reqBody&&Array.isArray(e.reqBody.params)?e.reqBody.params.map(p=>str(p.name)+'='+str(p.value)).join('\n'):''),sc:'reqb'},
 {id:'json',l:'JSON',r:tJson,body:1},
 {id:'xml',l:'XML',r:tXml,body:1},
 {id:'cookies',l:'Cookies',r:tCookies,txt:(e)=>hget(e.reqHeaders,'cookie'),sc:'reqh'},
 {id:'auth',l:'Auth',r:tAuth,txt:(e)=>authText(e),sc:'auth'},
 {id:'saml',l:'SAML',r:tSaml,txt:(e)=>e.auth&&Array.isArray(e.auth.saml)?e.auth.saml.map(s=>str(s.xml)).join('\n'):'',sc:'auth'},
 {id:'raw',l:'Raw',r:tRaw,txt:(e,m)=>hdrText(e.reqHeaders)+'\n'+bodyText(e,'req',m),sc:'reqb'},
 {id:'hex',l:'Hex',r:tHex}
];
const RESP_TABS=[
 {id:'headers',l:'Headers',r:tHeaders,txt:(e)=>hdrText(e.respHeaders),sc:'resh'},
 {id:'text',l:'TextView',r:tText,body:1},
 {id:'json',l:'JSON',r:tJson,body:1},
 {id:'xml',l:'XML',r:tXml,body:1},
 {id:'preview',l:'Preview',r:tPreview},
 {id:'cookies',l:'Cookies',r:tCookies,txt:(e)=>(Array.isArray(e.respCookies)?e.respCookies.map(c=>str(c.name)+'='+str(c.value)).join('\n'):'')+'\n'+hget(e.respHeaders,'set-cookie'),sc:'resh'},
 {id:'auth',l:'Auth',r:tAuth,txt:(e)=>authText(e),sc:'auth'},
 {id:'raw',l:'Raw',r:tRaw,txt:(e,m)=>hdrText(e.respHeaders)+'\n'+bodyText(e,'resp',m),sc:'resb'},
 {id:'hex',l:'Hex',r:tHex},
 {id:'timing',l:'Timing',r:tTiming},
 {id:'redirects',l:'Redirects',r:tRedirects},
 {id:'caching',l:'Caching',r:tCaching},
 {id:'ws',l:'WebSocket',r:tWebSocket,cond:e=>Array.isArray(e.wsMessages)&&e.wsMessages.length>0,txt:(e)=>e.wsMessages.map(m=>str(m&&m.data)).join('\n'),sc:'resb'},
 {id:'insights',l:'Insights',r:tInsights,cond:e=>Array.isArray(e.insights)&&e.insights.length>0}
];
function bodyText(e,kind,mode){const b=getBody(e,kind);return b?(mode==='raw'?str(b.raw):(str(b.decoded)!==''?str(b.decoded):(isBin(b)?'':str(b.raw)))):'';}
function tabCount(e,kind,tab,mode){
  if(!reHL)return 0;
  let text='',scope=tab.sc;
  if(tab.body){scope=kind==='req'?'reqb':'resb';text=bodyText(e,kind,mode);}
  else if(tab.txt)text=tab.txt(e,mode);
  else return 0;
  if(scope==='auth'&&S.scope!=='all')return 0;
  const re=hlRe(scope);
  return re?countMatches(text,re):0;
}
function downloadName(e,kind){
  const b=getBody(e,kind)||{};
  let seg='body';
  try{seg=new URL(e.url).pathname.split('/').filter(Boolean).pop()||str(e.host)||'body';}catch(err){}
  seg=seg.replace(/[^\w.\-]/g,'_').slice(0,60)||'body';
  if(/\.\w{1,5}$/.test(seg))return seg;
  const mt=str(kind==='resp'?e.mimeType:'').toLowerCase();
  const ext=b.format==='json'?'.json':b.format==='xml'?'.xml':b.format==='html'?'.html':/png/.test(mt)?'.png':/jpe?g/.test(mt)?'.jpg':/gif/.test(mt)?'.gif':/webp/.test(mt)?'.webp':/pdf/.test(mt)?'.pdf':b.format==='binary'?'.bin':'.txt';
  return seg+ext;
}
function downloadBody(e,kind,mode){
  const bv=bodyView(e,kind,mode);
  const b=getBody(e,kind);
  if(!b||(bv.msg&&!bv.bin)){toast('No body to download');return;}
  let u=null;
  if(isBin(b)||!bv.text){try{u=bodyBytes(e,kind,mode);}catch(err){}}
  if(u)saveBlob(downloadName(e,kind),'application/octet-stream',u);
  else saveBlob(downloadName(e,kind),'text/plain;charset=utf-8',bv.text);
}

/* ---------- inspector ---------- */
const INSPS=[];
function makeInspector(kind,host){
  const tabs=kind==='req'?REQ_TABS:RESP_TABS;
  let cur=LS.get('harui:tab:'+kind,'headers');
  let mode='decoded',curE=null,copyTxt='';
  const tabsEl=el('div',{class:'itabs',role:'tablist'});
  const bCopy=el('button',{title:'Copy this view'},'Copy');
  const bWrap=el('button',{title:'Word wrap on/off'},'Wrap');
  const bMode=el('button',{title:'Switch between raw and decoded body'},'Show raw');
  const bDl=el('button',{title:'Download the body'},'Download');
  const body=el('div',{class:'ibody',tabindex:'0'});
  host.appendChild(el('div',{class:'ihead'},el('span',{class:'nm'},kind==='req'?'Request':'Response'),tabsEl,el('div',{class:'ibtns'},bCopy,bWrap,bMode,bDl)));
  host.appendChild(body);
  bCopy.addEventListener('click',()=>copyText(copyTxt));
  bWrap.addEventListener('click',()=>{UI.wrap=!UI.wrap;saveUI();INSPS.forEach(i=>i.syncWrap());});
  bMode.addEventListener('click',()=>{mode=mode==='raw'?'decoded':'raw';bMode.textContent=mode==='raw'?'Show decoded':'Show raw';render(curE);});
  bDl.addEventListener('click',()=>{if(curE)downloadBody(curE,kind,mode);});
  function syncWrap(){body.classList.toggle('wrap',!!UI.wrap);bWrap.classList.toggle('on',!!UI.wrap);}
  function render(e){
    curE=e;
    tabsEl.textContent='';
    body.textContent='';
    copyTxt='';
    const vis=tabs.filter(t=>!t.cond||(e&&t.cond(e)));
    if(!vis.some(t=>t.id===cur))cur='headers';
    vis.forEach(t=>{
      const n=e?tabCount(e,kind,t,mode):0;
      const tb=el('div',{class:'tab'+(t.id===cur?' on':''),role:'tab'},t.l,n?el('span',{class:'dot',title:n+' match(es) in this tab'},n>=999?'999+':String(n)):null);
      tb.addEventListener('click',()=>{cur=t.id;LS.set('harui:tab:'+kind,cur);render(curE);});
      tabsEl.appendChild(tb);
    });
    syncWrap();
    if(!e){body.appendChild(empty('Select a session in the grid.'));return;}
    const t=vis.find(x=>x.id===cur);
    const ctx={kind,mode,copy:'',rerender:()=>render(curE)};
    let out;
    try{out=t.r(e,ctx);}catch(err){out=note('This tab could not be rendered: '+err.message);}
    body.appendChild(out);
    copyTxt=ctx.copy||'';
    const mk=body.querySelector('mark');
    if(mk){
      const br=body.getBoundingClientRect(),mr=mk.getBoundingClientRect();
      body.scrollTop=Math.max(0,mr.top-br.top+body.scrollTop-body.clientHeight/3);
      body.scrollLeft=Math.max(0,mr.left-br.left+body.scrollLeft-body.clientWidth/3);
    }
  }
  const api={render,syncWrap,focus:()=>body.focus()};
  INSPS.push(api);
  return api;
}


/* ---------- left panels ---------- */
let reqInsp,respInsp,leftTab='sessions',panelsDirty=true;
const LTABS=[['sessions','Sessions'],['summary','Summary'],['timeline','Timeline'],['insights','Insights'],['correlation','Correlation'],['info','Capture info']];
const lpanel=$('#lpanel');
function buildLeftTabs(){
  const h=$('#ltabs');
  h.textContent='';
  LTABS.forEach(t=>{
    const b=el('div',{class:'tab'+(leftTab===t[0]?' on':''),role:'tab'},t[1]);
    b.addEventListener('click',()=>showLeft(t[0]));
    h.appendChild(b);
  });
}
function showLeft(name){
  leftTab=name;
  buildLeftTabs();
  $('#gridwrap').style.display=name==='sessions'?'flex':'none';
  lpanel.style.display=name==='sessions'?'none':(name==='timeline'?'flex':'block');
  lpanel.style.flexDirection='column';
  lpanel.style.padding=name==='timeline'?'0':'8px';
  if(name==='sessions'){renderGrid(true);}else renderPanel(name);
}
function selectRow(e){return ()=>{select(e._i,{now:true});};}
function countBy(ents,fn){
  const m=new Map();
  ents.forEach(e=>{const k=fn(e);m.set(k,(m.get(k)||0)+1);});
  return Array.from(m.entries()).sort((a,b)=>b[1]-a[1]);
}
function countTable(pairs,max){
  const t=el('table',{class:'t'});
  const top=pairs.slice(0,max||15),mx=top.length?top[0][1]:1;
  top.forEach(p=>t.appendChild(el('tr',null,el('td',null,str(p[0])),el('td',{style:'width:1%;text-align:right'},String(p[1])),el('td',{style:'width:40%'},el('span',{class:'bar',style:'width:'+Math.max(1,p[1]/mx*100)+'%'})))));
  return t;
}
function entryTable(list,valFn,valHead){
  const t=el('table',{class:'t'});
  t.appendChild(el('tr',null,el('th',null,'#'),el('th',null,valHead),el('th',null,'Status'),el('th',null,'URL')));
  list.forEach(e=>{
    const r=el('tr',{class:'clk'},el('td',null,String(e.id)),el('td',{style:'white-space:nowrap'},valFn(e)),el('td',null,String(e._status)),el('td',{class:'v',style:'font-family:inherit'},redactText(e.url).slice(0,160)));
    r.addEventListener('click',selectRow(e));
    t.appendChild(r);
  });
  return t;
}
function renderPanel(name){
  lpanel.textContent='';
  panelsDirty=false;
  try{
    if(name==='summary')panelSummary();
    else if(name==='timeline')panelTimeline();
    else if(name==='insights')panelInsights();
    else if(name==='correlation')panelCorrelation();
    else if(name==='info')panelInfo();
  }catch(err){lpanel.appendChild(note('Panel failed: '+err.message));}
}
function panelSummary(){
  const ents=viewEntries(),n=ents.length;
  lpanel.appendChild(el('h3',null,'Overview'+(n!==N?' (filtered: '+n+' of '+N+')':'')));
  if(!n){lpanel.appendChild(empty('No sessions match the current filters.'));return;}
  const failed=ents.filter(e=>e._status>=400||e._fail).length;
  const ds=ents.map(e=>e._dur).sort((a,b)=>a-b);
  const med=ds.length%2?ds[(ds.length-1)/2]:(ds[ds.length/2-1]+ds[ds.length/2])/2;
  const xfer=ents.reduce((a,e)=>a+(e._xfer>=0?e._xfer:e._size),0);
  let t0=Infinity,t1=0;
  ents.forEach(e=>{if(e._t>0){t0=Math.min(t0,e._t);t1=Math.max(t1,e._t+e._dur);}});
  const cards=el('div',{class:'cards'});
  [['Requests',n],['Failed (4xx/5xx/0)',failed],['Total duration',fmtMs(ds.reduce((a,b)=>a+b,0))],['Median duration',fmtMs(med)],['Transfer size',fmtBytes(xfer)],['Unique hosts',new Set(ents.map(e=>e.host)).size],['Capture span',isFinite(t0)?fmtMs(t1-t0):'n/a']].forEach(c=>cards.appendChild(el('div',{class:'card'},el('b',null,String(c[1])),el('span',null,c[0]))));
  lpanel.appendChild(cards);
  lpanel.appendChild(el('h3',null,'Top 10 slowest'));
  lpanel.appendChild(entryTable(ents.slice().sort((a,b)=>b._dur-a._dur).slice(0,10),e=>fmtMs(e._dur),'Duration'));
  lpanel.appendChild(el('h3',null,'Top 10 largest'));
  lpanel.appendChild(entryTable(ents.slice().sort((a,b)=>b._size-a._size).slice(0,10),e=>fmtBytes(e._size),'Size'));
  lpanel.appendChild(el('h3',null,'Requests by host'));
  lpanel.appendChild(countTable(countBy(ents,e=>e.host||'(none)'),15));
  lpanel.appendChild(el('h3',null,'Requests by status'));
  lpanel.appendChild(countTable(countBy(ents,e=>e._status||'0 / failed').sort((a,b)=>String(a[0])<String(b[0])?-1:1),30));
  lpanel.appendChild(el('h3',null,'Requests by type'));
  lpanel.appendChild(countTable(countBy(ents,e=>e.resourceType||'other'),15));
}
function panelInfo(){
  lpanel.appendChild(el('h3',null,'Capture metadata'));
  const rows=[['Source file',meta.sourceFile],['Report generated',meta.generatedAt],['HAR version',meta.harVersion],['Creator',typeof meta.creator==='object'?JSON.stringify(meta.creator):meta.creator],['Browser',typeof meta.browser==='object'?JSON.stringify(meta.browser):meta.browser],['Capture start',meta.captureStart],['Capture end',meta.captureEnd],['Sessions',N],['Secrets redacted at generation',meta.redacted?'yes':'no']].filter(r=>r[1]!=null&&r[1]!=='');
  lpanel.appendChild(kvTable(rows,null));
  if(pagesMeta.length){
    lpanel.appendChild(el('h3',null,'Pages'));
    lpanel.appendChild(gridTable(['Id','Title','Started'],pagesMeta.map(p=>[str(p.id),str(p.title),str(p.startedDateTime)]),null));
  }
}
function panelInsights(){
  const ents=viewEntries();
  const rows=[];
  ents.forEach(e=>(Array.isArray(e.insights)?e.insights:[]).forEach(x=>rows.push({e,sev:str(x&&x.severity)||'info',msg:str(x&&x.message)})));
  lpanel.appendChild(el('h3',null,'Insights ('+rows.length+' in '+ents.length+' sessions)'));
  const cnt={error:0,warning:0,info:0};
  rows.forEach(r=>{if(cnt[r.sev]!=null)cnt[r.sev]++;});
  const codes=new Map();
  rows.forEach(r=>{(r.msg.match(/AADSTS\d+/g)||[]).forEach(c=>codes.set(c,(codes.get(c)||0)+1));});
  const sel=el('select',null,el('option',{value:''},'All severities'),el('option',{value:'error'},'Errors ('+cnt.error+')'),el('option',{value:'warning'},'Warnings ('+cnt.warning+')'),el('option',{value:'info'},'Info ('+cnt.info+')'));
  const box=el('div');
  lpanel.appendChild(sel);
  if(codes.size){
    lpanel.appendChild(el('h3',null,'AADSTS codes'));
    lpanel.appendChild(countTable(Array.from(codes.entries()).sort((a,b)=>b[1]-a[1]),20));
  }
  lpanel.appendChild(el('h3',null,'Details'));
  lpanel.appendChild(box);
  const draw=()=>{
    box.textContent='';
    const f=rows.filter(r=>!sel.value||r.sev===sel.value);
    if(!f.length){box.appendChild(empty('No insights.'));return;}
    const t=el('table',{class:'t'});
    t.appendChild(el('tr',null,el('th',null,''),el('th',null,'#'),el('th',null,'Message'),el('th',null,'URL')));
    f.slice(0,3000).forEach(r=>{
      const tr=el('tr',{class:'clk'},el('td',null,el('span',{class:'ins-'+r.sev},INS_ICON[r.sev]||'')),el('td',null,String(r.e.id)),el('td',null,r.msg),el('td',{style:'word-break:break-all'},redactText(r.e.url).slice(0,140)));
      tr.addEventListener('click',selectRow(r.e));
      t.appendChild(tr);
    });
    box.appendChild(t);
    if(f.length>3000)box.appendChild(note('Showing the first 3000 of '+f.length+' insights.'));
  };
  sel.addEventListener('change',draw);
  draw();
}
function corrText(e){
  const lines=[];
  if(e.correlation)for(const k in e.correlation){const v=str(e.correlation[k]);if(v)lines.push(k+': '+v);}
  const d=hget(e.respHeaders,'date');
  if(d&&!(e.correlation&&e.correlation.date))lines.push('Date: '+d);
  if(!lines.length)return '';
  return 'Request: '+e.method+' '+redactText(e.url)+'\nTime: '+(fmtTs(e._t,'UTC'))+' UTC\nStatus: '+e._status+'\n'+lines.join('\n');
}
function panelCorrelation(){
  lpanel.appendChild(el('h3',null,'Correlation IDs'));
  if(selI>=0){
    const e=E[selI],t=corrText(e);
    lpanel.appendChild(el('div',{style:'margin-bottom:6px'},el('b',null,'Selected #'+e.id+': '),t?el('button',{onclick:()=>copyText(t)},'Copy for support case'):'no correlation IDs'));
  }
  const rows=[];
  viewEntries().forEach(e=>{if(e.correlation)for(const k in e.correlation){const v=str(e.correlation[k]);if(v)rows.push([e,k,v]);}});
  lpanel.appendChild(el('div',{style:'margin-bottom:6px'},el('button',{onclick:()=>copyText(rows.map(r=>'#'+r[0].id+' '+r[1]+': '+r[2]).join('\n'))},'Copy all visible ('+rows.length+')')));
  if(!rows.length){lpanel.appendChild(empty('No correlation IDs in the visible sessions.'));return;}
  const t=el('table',{class:'t'});
  t.appendChild(el('tr',null,el('th',null,'#'),el('th',null,'Header'),el('th',null,'Value'),el('th',null,'URL'),el('th',null,'')));
  rows.slice(0,3000).forEach(r=>{
    const cb=el('button',{class:'copybtn',onclick:ev=>{ev.stopPropagation();copyText(r[2]);}},'Copy');
    const tr=el('tr',{class:'clk'},el('td',null,String(r[0].id)),el('td',null,r[1]),el('td',{class:'v'},r[2]),el('td',{style:'word-break:break-all'},redactText(pathQ(r[0])).slice(0,100)),el('td',null,cb));
    tr.addEventListener('click',selectRow(r[0]));
    t.appendChild(tr);
  });
  lpanel.appendChild(t);
  if(rows.length>3000)lpanel.appendChild(note('Showing the first 3000 rows.'));
}

/* ---------- timeline ---------- */
let TL=null;
function panelTimeline(){
  const wrap=el('div',{id:'tlwrap'});
  const sp=el('div',{id:'tlsp'});
  const cv=el('canvas',{id:'tlcv'});
  wrap.appendChild(sp);wrap.appendChild(cv);
  const info=el('div',{style:'padding:2px 8px;font-size:11px;border-top:1px solid var(--bd);background:var(--pane);min-height:20px;flex:none'},'Click a bar to select the session.');
  lpanel.appendChild(wrap);lpanel.appendChild(info);
  TL={wrap,sp,cv,info,list:[]};
  wrap.addEventListener('scroll',()=>{if(!TL.raf)TL.raf=requestAnimationFrame(()=>{TL.raf=0;drawTimeline();});});
  const rowAt=ev=>{const r=cv.getBoundingClientRect();const i=Math.floor((ev.clientY-r.top-22+wrap.scrollTop)/18);return i>=0&&i<TL.list.length?TL.list[i]:null;};
  cv.addEventListener('click',ev=>{const e=rowAt(ev);if(e)select(e._i,{now:true,scroll:true});});
  cv.addEventListener('mousemove',ev=>{const e=rowAt(ev);info.textContent=e?'#'+e.id+'  '+e.method+'  '+(e._status||0)+'  '+fmtMs(e._dur)+'  '+redactText(e.url).slice(0,200):'Click a bar to select the session.';});
  drawTimeline();
}
function drawTimeline(){
  if(!TL||leftTab!=='timeline'||!TL.wrap.isConnected)return;
  const {wrap,sp,cv}=TL;
  const RHT=18,AX=22,LW=Math.min(260,Math.max(120,wrap.clientWidth*0.3));
  TL.list=viewEntries();
  const list=TL.list;
  sp.style.height=(list.length*RHT+AX)+'px';
  const W=wrap.clientWidth,H=wrap.clientHeight;
  if(W<10||H<10)return;
  const dpr=window.devicePixelRatio||1;
  cv.width=Math.round(W*dpr);cv.height=Math.round(H*dpr);
  cv.style.width=W+'px';cv.style.height=H+'px';
  const g=cv.getContext('2d');
  g.setTransform(dpr,0,0,dpr,0,0);
  const cs=getComputedStyle(document.body);
  const fg=cs.getPropertyValue('--fg').trim()||'#000',bg=cs.getPropertyValue('--bg').trim()||'#fff',mut=cs.getPropertyValue('--mut').trim()||'#666',bd=cs.getPropertyValue('--bd').trim()||'#ccc',sel=cs.getPropertyValue('--sel').trim()||'#316ac5',red=cs.getPropertyValue('--red').trim()||'#c00';
  g.fillStyle=bg;g.fillRect(0,0,W,H);
  if(!list.length){g.fillStyle=mut;g.font='12px Segoe UI, sans-serif';g.fillText('No sessions in the current view.',10,40);return;}
  let t0=Infinity,t1=0;
  list.forEach(e=>{if(e._t>0){t0=Math.min(t0,e._t);t1=Math.max(t1,e._t+e._dur);}});
  if(!isFinite(t0)){t0=0;t1=1;}
  const span=Math.max(1,t1-t0),px=(W-LW-12)/span;
  const st=wrap.scrollTop,first=Math.max(0,Math.floor(st/RHT)-1),last=Math.min(list.length,Math.ceil((st+H)/RHT)+1);
  g.font='11px Segoe UI, sans-serif';g.textBaseline='middle';
  for(let i=first;i<last;i++){
    const e=list[i],y=AX+i*RHT-st;
    if(e._i===selI){g.fillStyle=sel;g.globalAlpha=0.25;g.fillRect(0,y,W,RHT);g.globalAlpha=1;}
    g.save();g.beginPath();g.rect(0,y,LW-4,RHT);g.clip();
    g.fillStyle=(e._status>=400||e._fail)?red:fg;
    g.fillText('#'+e.id+' '+pathQ(e).slice(0,80),4,y+RHT/2);
    g.restore();
    let x=LW+(e._t-t0)*px;
    const pv=phaseVals(e).v;
    const sum=PH.reduce((a,p)=>a+pv[p[0]],0);
    if(sum>0){
      const sc=e._dur>0?e._dur/sum:1;
      PH.forEach(p=>{const w=pv[p[0]]*sc*px;if(w>0){g.fillStyle=p[2];g.fillRect(x,y+3,Math.max(1,w),RHT-6);x+=w;}});
    }else{
      g.fillStyle=(e._status>=400||e._fail)?red:mut;
      g.fillRect(x,y+3,Math.max(2,e._dur*px),RHT-6);
    }
  }
  g.fillStyle=bg;g.fillRect(0,0,W,AX);
  g.fillStyle=mut;g.strokeStyle=bd;
  for(let k=0;k<=6;k++){
    const x=LW+(W-LW-12)*k/6;
    g.beginPath();g.moveTo(x,AX-4);g.lineTo(x,AX);g.stroke();
    g.fillText('+'+fmtMs(span*k/6),Math.min(x+2,W-60),AX/2-1);
  }
  g.beginPath();g.moveTo(0,AX-0.5);g.lineTo(W,AX-0.5);g.stroke();
  g.fillStyle=fg;g.fillText('Session',4,AX/2-1);
}
new ResizeObserver(()=>{if(leftTab==='timeline')drawTimeline();renderGridSoon();}).observe(lpanel);
let rgs=0;
function renderGridSoon(){if(rgs)return;rgs=requestAnimationFrame(()=>{rgs=0;renderGrid(true);});}

/* ---------- compare ---------- */
function diffLines(a,b){
  let s=0;
  while(s<a.length&&s<b.length&&a[s]===b[s])s++;
  let ea=a.length,eb=b.length;
  while(ea>s&&eb>s&&a[ea-1]===b[eb-1]){ea--;eb--;}
  const A=a.slice(s,ea),B=b.slice(s,eb);
  const ops=[];
  for(let i=0;i<s;i++)ops.push(['eq',a[i],a[i]]);
  const n=A.length,m=B.length;
  if(n*m>4000000){
    for(let i=0;i<Math.max(n,m);i++){
      if(i<n&&i<m)ops.push([A[i]===B[i]?'eq':'chg',A[i],B[i]]);
      else if(i<n)ops.push(['del',A[i],'']);
      else ops.push(['add','',B[i]]);
    }
  }else{
    const w=m+1,dp=new Uint32Array((n+1)*w);
    for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)dp[i*w+j]=A[i]===B[j]?dp[(i+1)*w+j+1]+1:Math.max(dp[(i+1)*w+j],dp[i*w+j+1]);
    let i=0,j=0;const raw=[];
    while(i<n&&j<m){
      if(A[i]===B[j]){raw.push(['eq',A[i],B[j]]);i++;j++;}
      else if(dp[(i+1)*w+j]>=dp[i*w+j+1]){raw.push(['del',A[i],'']);i++;}
      else{raw.push(['add','',B[j]]);j++;}
    }
    while(i<n)raw.push(['del',A[i++],'']);
    while(j<m)raw.push(['add','',B[j++]]);
    for(let k=0;k<raw.length;k++){
      if(raw[k][0]==='del'){
        let d0=k;while(k<raw.length&&raw[k][0]==='del')k++;
        let a0=k;while(k<raw.length&&raw[k][0]==='add')k++;
        const dels=raw.slice(d0,a0),adds=raw.slice(a0,k);
        const c=Math.min(dels.length,adds.length);
        for(let x=0;x<c;x++)ops.push(['chg',dels[x][1],adds[x][2]]);
        for(let x=c;x<dels.length;x++)ops.push(dels[x]);
        for(let x=c;x<adds.length;x++)ops.push(adds[x]);
        k--;
      }else ops.push(raw[k]);
    }
  }
  for(let i=ea;i<a.length;i++)ops.push(['eq',a[i],a[i]]);
  return ops;
}
function diffTable(ops,labels){
  const t=el('table',{class:'diffgrid'});
  t.appendChild(el('tr',null,el('th',{style:'width:50%'},labels[0]),el('th',{style:'width:50%'},labels[1])));
  const near=new Array(ops.length).fill(false);
  ops.forEach((o,i)=>{if(o[0]!=='eq')for(let k=Math.max(0,i-3);k<=Math.min(ops.length-1,i+3);k++)near[k]=true;});
  let hidden=0;
  const flush=()=>{if(hidden){t.appendChild(el('tr',null,el('td',{colspan:2,style:'color:var(--mut);text-align:center'},'\u2026 '+hidden+' identical line(s) \u2026')));hidden=0;}};
  ops.forEach((o,i)=>{
    if(o[0]==='eq'&&!near[i]){hidden++;return;}
    flush();
    t.appendChild(el('tr',{class:o[0]==='eq'?'':o[0]},el('td',{class:'a'},o[1]),el('td',{class:'b'},o[2])));
  });
  flush();
  if(ops.every(o=>o[0]==='eq'))t.appendChild(el('tr',null,el('td',{colspan:2,style:'color:var(--mut);text-align:center'},'Identical')));
  return t;
}
function hdrOps(la,lb){
  const m=l=>{const r=new Map();l.forEach(h=>{const k=str(h.name).toLowerCase();const v=redactHeader(str(h.name),str(h.value));r.set(k,{n:str(h.name),v:r.has(k)?r.get(k).v+', '+v:v});});return r;};
  const A=m(la),B=m(lb);
  const keys=Array.from(new Set([...A.keys(),...B.keys()])).sort();
  return keys.map(k=>{
    const a=A.get(k),b=B.get(k);
    const at=a?a.n+': '+a.v:'',bt=b?b.n+': '+b.v:'';
    return [!a?'add':!b?'del':at===bt?'eq':'chg',at,bt];
  });
}
function bodyLines(e,kind){
  let t=bodyText(e,kind,'decoded');
  if(!t)return [bodyView(e,kind,'decoded').msg];
  t=redactText(t);
  try{t=JSON.stringify(JSON.parse(t),null,2);}catch(err){if(looksXml(t)&&t.length<CAP)t=formatXml(t);}
  const l=t.split(/\r?\n/);
  return l.length>5000?l.slice(0,5000).concat(['\u2026 truncated for comparison \u2026']):l;
}
function openCompare(ai,bi){
  const A=E[ai],B=E[bi];
  const root=el('div');
  const L=['#'+A.id+'  '+A.method+' '+(A._status||0),'#'+B.id+'  '+B.method+' '+(B._status||0)];
  const gen=(e)=>['Method: '+e.method,'URL: '+redactText(e.url),'Status: '+e._status+' '+str(e.statusText),'Protocol: '+str(e.httpVersion),'Content-Type: '+e._ct,'Duration: '+fmtMs(e._dur),'Body size: '+fmtBytes(e._size),'Server IP: '+str(e.serverIp)];
  root.appendChild(sec('General'));
  const ga=gen(A),gb=gen(B);
  root.appendChild(diffTable(ga.map((x,i)=>[x===gb[i]?'eq':'chg',x,gb[i]]),L));
  const qp=e=>(Array.isArray(e.queryParams)?e.queryParams:[]).map(p=>str(p.name)+'='+redactVal(str(p.name),str(p.value))).sort();
  root.appendChild(sec('Query parameters'));
  root.appendChild(diffTable(diffLines(qp(A),qp(B)),L));
  root.appendChild(sec('Request headers'));
  root.appendChild(diffTable(hdrOps(A.reqHeaders,B.reqHeaders),L));
  root.appendChild(sec('Request body'));
  root.appendChild(diffTable(diffLines(bodyLines(A,'req'),bodyLines(B,'req')),L));
  root.appendChild(sec('Response headers'));
  root.appendChild(diffTable(hdrOps(A.respHeaders,B.respHeaders),L));
  root.appendChild(sec('Response body'));
  root.appendChild(diffTable(diffLines(bodyLines(A,'resp'),bodyLines(B,'resp')),L));
  openModal('Compare sessions #'+A.id+' and #'+B.id,root,true);
}

/* ---------- copy as ---------- */
const shq=s=>"'"+String(s).replace(/'/g,"'\\''")+"'";
const psq=s=>"'"+String(s).replace(/(['\u2018\u2019\u201A\u201B])/g,'$1$1')+"'";
function reqBodyForCopy(e){
  const b=e.reqBody;
  if(!b||isBin(b))return '';
  const t=str(b.decoded)!==''?str(b.decoded):str(b.raw);
  return redactText(t);
}
function asCurl(e){
  const p=['curl'];
  const m=String(e.method).toUpperCase();
  if(m!=='GET')p.push('-X '+shq(m));
  p.push(shq(redactText(e.url)));
  e.reqHeaders.forEach(h=>{
    const n=str(h.name);
    if(n[0]===':'||/^(content-length|host)$/i.test(n))return;
    p.push('-H '+shq(n+': '+redactHeader(n,str(h.value))));
  });
  const body=reqBodyForCopy(e);
  if(body)p.push('--data-raw '+shq(body));
  if(/gzip|br|deflate/i.test(hget(e.reqHeaders,'accept-encoding')))p.push('--compressed');
  return p.join(' \\\n  ');
}
function asPowerShell(e){
  const m=String(e.method).toUpperCase();
  const hs=new Map();
  let ct='',ua='';
  e.reqHeaders.forEach(h=>{
    const n=str(h.name),l=n.toLowerCase();
    if(n[0]===':'||/^(content-length|host)$/.test(l))return;
    const v=redactHeader(n,str(h.value));
    if(l==='content-type'){ct=v;return;}
    if(l==='user-agent'){ua=v;return;}
    hs.set(n,hs.has(n)?hs.get(n)+', '+v:v);
  });
  let s='';
  if(hs.size){
    s+='$headers = @{\n';
    hs.forEach((v,k)=>{s+='  '+psq(k)+' = '+psq(v)+'\n';});
    s+='}\n';
  }
  const std=['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'];
  const parts=['Invoke-WebRequest','-Uri '+psq(redactText(e.url))];
  parts.push(std.indexOf(m)>=0?'-Method '+m[0]+m.slice(1).toLowerCase():'-CustomMethod '+psq(m));
  if(hs.size)parts.push('-Headers $headers');
  if(ct)parts.push('-ContentType '+psq(ct));
  if(ua)parts.push('-UserAgent '+psq(ua));
  const body=reqBodyForCopy(e);
  if(body)parts.push('-Body '+psq(body));
  return s+parts.join(' `\n  ');
}

/* ---------- export ---------- */
function csvCell(v,textual){
  let s=str(v);
  if(textual&&/^[=+\-@\t\r]/.test(s))s="'"+s;
  return /[",\r\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;
}
function exportCsv(){
  const head=['#','Started (UTC)','Method','Status','URL','Host','Protocol','Content-Type','Type','Body size (bytes)','Transfer size (bytes)','Duration (ms)','Server IP','Cache','Correlation ID','Insights'];
  const lines=[head.join(',')];
  viewEntries().forEach(e=>{
    lines.push([e.id,fmtTs(e._t,'UTC'),e.method,e._status,redactText(e.url),e.host,e.httpVersion,e._ct,e.resourceType,e._size,e._xfer>=0?e._xfer:'',Math.round(e._dur),e.serverIp,e._cache,e._corr1,(Array.isArray(e.insights)?e.insights:[]).map(x=>str(x.severity)+': '+str(x.message)).join(' | ')].map((v,i)=>csvCell(v,[2,4,5,6,7,8,12,13,14,15].indexOf(i)>=0)).join(','));
  });
  saveBlob('sessions.csv','text/csv;charset=utf-8','\uFEFF'+lines.join('\r\n'));
}
function exportSession(){
  if(selI<0){toast('Select a session first');return;}
  const e=E[selI];
  saveBlob('session_'+e.id+'.txt','text/plain;charset=utf-8',rawRequestText(e,'decoded')+'\r\n\r\n'+'-'.repeat(60)+'\r\n\r\n'+rawResponseText(e,'decoded'));
}
function harHeaders(l){return l.map(h=>({name:str(h.name),value:redactHeader(str(h.name),str(h.value))}));}
function harEntry(e){
  const rq=e.reqBody||{},rs=e.respBody||{};
  const t=e.timings||{};
  const tv=k=>{const v=Number(t[k]);return isFinite(v)?v:-1;};
  const req={method:e.method,url:redactText(e.url),httpVersion:str(e.httpVersion)||'HTTP/1.1',cookies:(Array.isArray(e.reqCookies)?e.reqCookies:[]).map(c=>({name:str(c.name),value:UI.redact?mask(c.value):str(c.value)})),headers:harHeaders(e.reqHeaders),queryString:(Array.isArray(e.queryParams)?e.queryParams:[]).map(p=>({name:str(p.name),value:redactVal(str(p.name),str(p.value))})),headersSize:-1,bodySize:num(rq.size)};
  const rt=reqBodyForCopy(e);
  if(rt)req.postData={mimeType:hget(e.reqHeaders,'content-type'),text:rt};
  const content={size:num(rs.size),mimeType:e._ct};
  if(rs.b64&&isBin(rs)){content.text=rs.b64;content.encoding='base64';}
  else{const tx=str(rs.decoded)!==''?str(rs.decoded):str(rs.raw);if(tx)content.text=redactText(tx);}
  return {pageref:e.pageRef!=null?e.pageRef:undefined,startedDateTime:str(e.startedDateTime)||new Date(e._t).toISOString(),time:e._dur,request:req,
    response:{status:e._status,statusText:str(e.statusText),httpVersion:str(e.httpVersion)||'HTTP/1.1',cookies:(Array.isArray(e.respCookies)?e.respCookies:[]).map(c=>({name:str(c.name),value:UI.redact?mask(c.value):str(c.value),path:c.path,domain:c.domain,expires:c.expires,httpOnly:!!c.httpOnly,secure:!!c.secure})),headers:harHeaders(e.respHeaders),content:content,redirectURL:str(e.redirectURL),headersSize:-1,bodySize:e._xfer>=0?e._xfer:-1},
    cache:{},timings:{blocked:tv('blocked'),dns:tv('dns'),connect:tv('connect'),ssl:tv('ssl'),send:Math.max(0,tv('send')),wait:Math.max(0,tv('wait')),receive:Math.max(0,tv('receive'))},
    serverIPAddress:str(e.serverIp),connection:str(e.connection),_resourceType:e.resourceType};
}
function exportHar(){
  const ents=viewEntries();
  const used=new Set(ents.map(e=>e.pageRef));
  const har={log:{version:'1.2',creator:{name:'HAR2HTML report export',version:'1.0'},pages:pagesMeta.filter(p=>used.has(p.id)).map(p=>({startedDateTime:str(p.startedDateTime),id:str(p.id),title:str(p.title),pageTimings:{}})),entries:ents.map(harEntry)}};
  const base=str(meta.sourceFile).replace(/\.har$/i,'').replace(/[^\w.\-]/g,'_')||'report';
  saveBlob(base+'_filtered.har','application/json',JSON.stringify(har,null,2));
}

/* ---------- help ---------- */
function openHelp(){
  const root=el('div');
  const k=t=>el('span',{class:'kbd'},t);
  const rows=[[[k('\u2191'),' / ',k('\u2193')],'Previous / next session'],[[k('Enter')],'Focus the inspector'],[[k('Ctrl+F')],'Focus search'],[[k('F3'),' / ',k('Shift+F3')],'Next / previous match'],[[k('Esc')],'Clear search, close menus and dialogs'],[[k('?')],'This help'],[[k('Ctrl+click')],'Mark a second session for Compare'],[['Right-click'],'Context menu (copy, mark, host filter, compare)']];
  const t=el('table',{class:'t'});
  rows.forEach(r=>{const a=el('td',{class:'k'});const b=el('td');
    add(a,r[0]);
    b.textContent=r[1];t.appendChild(el('tr',null,a,b));});
  root.appendChild(el('h3',null,'Keyboard shortcuts'));
  root.appendChild(t);
  root.appendChild(el('h3',null,'Legend'));
  const lg=[['4xx / 5xx','red text'],['3xx','purple text'],['304','grey text'],['Status 0 / failed','red italic'],['CSS','purple'],['JS','green'],['Images','grey'],['Yellow row','search match'],['Blue row','selected session'],['\u2716 \u26A0 \u2139','insight: error / warning / info'],[TYPE_ICON.document+' '+TYPE_ICON.xhr+' '+TYPE_ICON.script,'document / XHR-fetch / script']];
  root.appendChild(kvTable(lg,null));
  root.appendChild(el('p',null,'Search covers URL, headers, bodies (raw and decoded) and decoded JWT/SAML content. Redact masks tokens, cookies and passwords on screen only. All data stays in this file; nothing is sent over the network.'));
  openModal('Help',root,false);
}


/* ---------- toolbar & init ---------- */
function applyTheme(){
  document.body.classList.toggle('dark',UI.theme==='dark');
  $('#bDark').textContent=UI.theme==='dark'?'Light':'Dark';
  $('#bDark').classList.toggle('on',UI.theme==='dark');
  if(leftTab==='timeline')drawTimeline();
}
function syncToggles(){
  $('#bColors').classList.toggle('on',!!UI.colors);
  $('#bRedact').classList.toggle('on',!!UI.redact);
  $('#bPages').classList.toggle('on',!!UI.pages);
  $('#bTime').textContent=UI.tz;
  $('#bCase').classList.toggle('on',S.cs);
  $('#bRe').classList.toggle('on',S.re);
  $('#bWord').classList.toggle('on',S.word);
  $$q('#qf button[data-q]').forEach(b=>b.classList.toggle('on',!!Q[b.getAttribute('data-q')]));
}
function $$q(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
function refreshAll(){
  renderGrid(true);updateSessbar();scheduleInspect(true);
  if(leftTab!=='sessions')renderPanel(leftTab);
}
function layoutSplit(){
  const left=$('#left'),main=$('#main');
  if(UI.leftPx>=200)left.style.width=Math.min(UI.leftPx,Math.max(200,main.clientWidth-210))+'px';
  const right=$('#right');
  const avail=right.clientHeight-$('#sessbar').offsetHeight-5;
  if(avail>120){
    const h=Math.max(60,Math.min(avail-60,Math.round(avail*UI.reqFrac)));
    $('#reqPane').style.flex='none';
    $('#reqPane').style.height=h+'px';
    $('#respPane').style.flex='1';
  }
}
function drag(handle,onMove,done){
  handle.addEventListener('mousedown',ev=>{
    ev.preventDefault();
    const mv=e2=>onMove(e2);
    const up=()=>{document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);document.body.style.userSelect='';done();};
    document.body.style.userSelect='none';
    document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);
  });
}
function init(){
  reqInsp=makeInspector('req',$('#reqPane'));
  respInsp=makeInspector('resp',$('#respPane'));
  applyTheme();
  const qi=$('#q');
  qi.addEventListener('input',()=>{S.q=qi.value;qDeb();});
  qi.addEventListener('keydown',ev=>{
    if(ev.key==='Enter'){
      ev.preventDefault();
      if(S.q&&MATCH&&matchPos.length&&selI>=0&&MATCH[selI]){gotoMatch(ev.shiftKey?-1:1);}
      else runSearch(true);
    }
  });
  const reRun=()=>{syncToggles();runSearch(false);};
  $('#bCase').addEventListener('click',()=>{S.cs=!S.cs;reRun();});
  $('#bRe').addEventListener('click',()=>{S.re=!S.re;reRun();});
  $('#bWord').addEventListener('click',()=>{S.word=!S.word;reRun();});
  $('#scope').addEventListener('change',ev=>{S.scope=ev.target.value;runSearch(false);});
  $('#onlyM').addEventListener('change',ev=>{S.onlyM=ev.target.checked;applyView();});
  $('#bNext').addEventListener('click',()=>gotoMatch(1));
  $('#bPrev').addEventListener('click',()=>gotoMatch(-1));
  $('#bTime').addEventListener('click',()=>{UI.tz=UI.tz==='Local'?'UTC':UI.tz==='UTC'?'Relative':'Local';saveUI();syncToggles();refreshAll();});
  $('#bColors').addEventListener('click',()=>{UI.colors=!UI.colors;saveUI();syncToggles();renderGrid(true);});
  $('#bRedact').addEventListener('click',()=>{UI.redact=!UI.redact;saveUI();syncToggles();refreshAll();});
  $('#bPages').addEventListener('click',()=>{UI.pages=!UI.pages;saveUI();syncToggles();applyView();});
  $('#bDark').addEventListener('click',()=>{UI.theme=UI.theme==='dark'?'light':'dark';saveUI();applyTheme();});
  $('#bHelp').addEventListener('click',openHelp);
  $('#bCompare').addEventListener('click',()=>{
    if(selI>=0&&cmpI>=0&&selI!==cmpI)openCompare(selI,cmpI);
    else toast('Select a session, then Ctrl+click a second session to compare');
  });
  $('#bCols').addEventListener('click',ev=>{
    ev.stopPropagation();
    showPopup($('#bCols'),()=>{
      const box=el('div');
      COLS.forEach(c=>{
        const cb=el('input',{type:'checkbox'});
        cb.checked=UI.vis.indexOf(c.k)>=0;cb.disabled=!!c.req;
        cb.addEventListener('change',()=>{
          UI.vis=UI.vis.filter(x=>x!==c.k);
          if(cb.checked)UI.vis.push(c.k);
          saveUI();layoutGrid();
        });
        box.appendChild(el('label',null,cb,' '+c.l+(c.req?' (required)':'')));
      });
      box.appendChild(el('div',{class:'mi',onclick:()=>{UI.vis=DEFVIS.slice();UI.order=COLS.map(c=>c.k);UI.widths={};saveUI();closePopup();layoutGrid();}},'Reset columns'));
      return box;
    });
  });
  $('#bExport').addEventListener('click',ev=>{
    ev.stopPropagation();
    showPopup($('#bExport'),()=>el('div',null,
      el('div',{class:'mi',onclick:()=>{closePopup();exportCsv();}},'Filtered list as CSV'),
      el('div',{class:'mi',onclick:()=>{closePopup();exportSession();}},'Selected session as .txt'),
      el('div',{class:'mi',onclick:()=>{closePopup();exportHar();}},'Filtered sessions as .har')));
  });
  $$q('#qf button[data-q]').forEach(b=>b.addEventListener('click',()=>{const k=b.getAttribute('data-q');Q[k]=!Q[k];b.classList.toggle('on',Q[k]);applyView();}));
  $('#slowN').addEventListener('input',ev=>{Q.slowN=num(ev.target.value);if(Q.slow)doFilter();});
  $('#largeN').addEventListener('input',ev=>{Q.largeKB=num(ev.target.value);if(Q.large)doFilter();});
  $('#bClear').addEventListener('click',()=>{
    F.text={};F.method.clear();F.cls.clear();F.exact=F.tFrom=F.tTo=F.dMin=F.dMax=F.sMin=F.sMax='';F.ins=false;
    Object.keys(Q).forEach(k=>{if(typeof Q[k]==='boolean')Q[k]=false;});
    S.q='';qi.value='';S.onlyM=false;$('#onlyM').checked=false;
    syncToggles();buildFilter();runSearch(false);
  });
  $('#sbMark').addEventListener('change',ev=>{if(selI>=0)setMark(E[selI],ev.target.value);});
  const saveNote=debounce(()=>{if(selI>=0)setMark(E[selI],undefined,$('#sbNote').value.trim());},400);
  $('#sbNote').addEventListener('input',saveNote);
  drag($('#vsplit'),ev=>{
    const r=$('#main').getBoundingClientRect();
    UI.leftPx=Math.max(200,Math.min(r.width-210,ev.clientX-r.left));
    $('#left').style.width=UI.leftPx+'px';
  },()=>{saveUI();renderGrid(true);if(leftTab==='timeline')drawTimeline();});
  drag($('#hsplit'),ev=>{
    const right=$('#right').getBoundingClientRect();
    const top=right.top+$('#sessbar').offsetHeight;
    const avail=right.height-$('#sessbar').offsetHeight-5;
    UI.reqFrac=Math.max(0.1,Math.min(0.9,(ev.clientY-top)/avail));
    layoutSplit();
  },saveUI);
  window.addEventListener('resize',()=>{layoutSplit();renderGrid(true);});
  window.addEventListener('hashchange',applyHash);
  document.addEventListener('keydown',ev=>{
    const t=ev.target,tag=t&&t.tagName;
    const typing=tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT';
    if(ev.key==='Escape'){
      closePopup();$('#ctx').style.display='none';
      if(modalEl){closeModal();return;}
      if(S.q||qi.value){S.q='';qi.value='';runSearch(false);}
      return;
    }
    if((ev.ctrlKey||ev.metaKey)&&(ev.key==='f'||ev.key==='F')){ev.preventDefault();qi.focus();qi.select();return;}
    if(ev.key==='F3'){ev.preventDefault();gotoMatch(ev.shiftKey?-1:1);return;}
    if(typing||ev.ctrlKey||ev.altKey||ev.metaKey)return;
    if(ev.key==='?'){ev.preventDefault();openHelp();return;}
    const inGrid=document.activeElement===gview||document.activeElement===document.body;
    if(!inGrid)return;
    if(ev.key==='ArrowDown'){ev.preventDefault();moveSel(1);}
    else if(ev.key==='ArrowUp'){ev.preventDefault();moveSel(-1);}
    else if(ev.key==='PageDown'){ev.preventDefault();moveSel(Math.max(1,Math.floor(gview.clientHeight/RH)-1));}
    else if(ev.key==='PageUp'){ev.preventDefault();moveSel(-Math.max(1,Math.floor(gview.clientHeight/RH)-1));}
    else if(ev.key==='Home'){ev.preventDefault();moveSel(-view.length);}
    else if(ev.key==='End'){ev.preventDefault();moveSel(view.length);}
    else if(ev.key==='Enter'){ev.preventDefault();respInsp.focus();}
  });
  syncToggles();
  buildLeftTabs();
  layoutGrid();
  applyView();
  layoutSplit();
  updateSessbar();
  reqInsp.render(null);respInsp.render(null);
  applyHash();
  if(selI<0&&N>0&&view.length){const f=view.find(i=>i>=0);if(f!=null)select(f,{now:true});}
}
init();
})();

</script>
</body>
</html>
'@
#endregion

#region Initialize-NativeHelpers
function Initialize-NativeHelpers {
if (-not ('HarFmt' -as [type])) {
    $csharp = @'
using System;
using System.Collections;
using System.Globalization;
using System.Text;

public static class HarFmt
{
    public static string ToJson(object o)
    {
        StringBuilder sb = new StringBuilder(1 << 20);
        Write(sb, o, 0);
        return sb.ToString();
    }

    static object Unwrap(object o)
    {
        if (o != null && o.GetType().FullName == "System.Management.Automation.PSObject")
        {
            System.Reflection.PropertyInfo p = o.GetType().GetProperty("BaseObject");
            if (p != null) { return p.GetValue(o, null); }
        }
        return o;
    }

    static void Write(StringBuilder sb, object o, int depth)
    {
        if (depth > 100) { sb.Append("null"); return; }
        o = Unwrap(o);
        if (o == null || o is DBNull) { sb.Append("null"); return; }
        string s = o as string;
        if (s != null) { Str(sb, s); return; }
        if (o is bool) { sb.Append(((bool)o) ? "true" : "false"); return; }
        if (o is char) { Str(sb, o.ToString()); return; }
        if (o is double)
        {
            double d = (double)o;
            if (double.IsNaN(d) || double.IsInfinity(d)) { sb.Append("0"); } else { sb.Append(d.ToString("R", CultureInfo.InvariantCulture)); }
            return;
        }
        if (o is float)
        {
            float f = (float)o;
            if (float.IsNaN(f) || float.IsInfinity(f)) { sb.Append("0"); } else { sb.Append(f.ToString("R", CultureInfo.InvariantCulture)); }
            return;
        }
        if (o is decimal || o is sbyte || o is byte || o is short || o is ushort || o is int || o is uint || o is long || o is ulong)
        {
            sb.Append(((IConvertible)o).ToString(CultureInfo.InvariantCulture));
            return;
        }
        if (o is DateTime) { Str(sb, ((DateTime)o).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)); return; }
        if (o is DateTimeOffset) { Str(sb, ((DateTimeOffset)o).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)); return; }
        IDictionary dict = o as IDictionary;
        if (dict != null)
        {
            sb.Append('{');
            bool first = true;
            foreach (DictionaryEntry de in dict)
            {
                if (!first) { sb.Append(','); }
                first = false;
                Str(sb, Convert.ToString(de.Key, CultureInfo.InvariantCulture));
                sb.Append(':');
                Write(sb, de.Value, depth + 1);
            }
            sb.Append('}');
            return;
        }
        IEnumerable en = o as IEnumerable;
        if (en != null)
        {
            sb.Append('[');
            bool first2 = true;
            foreach (object item in en)
            {
                if (!first2) { sb.Append(','); }
                first2 = false;
                Write(sb, item, depth + 1);
            }
            sb.Append(']');
            return;
        }
        Str(sb, o.ToString());
    }

    // Safe for embedding inside <script type="application/json">: escapes "</", "<!--" and U+2028/U+2029.
    static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        int n = s.Length;
        for (int i = 0; i < n; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '<':
                    if (i + 1 < n && s[i + 1] == '/') { sb.Append("<\\/"); i++; }
                    else if (i + 3 < n && s[i + 1] == '!' && s[i + 2] == '-' && s[i + 3] == '-') { sb.Append("<\\u0021--"); i += 3; }
                    else { sb.Append('<'); }
                    break;
                case '\u2028': sb.Append("\\u2028"); break;
                case '\u2029': sb.Append("\\u2029"); break;
                default:
                    if (c < 0x20) { sb.Append("\\u").Append(((int)c).ToString("x4")); } else { sb.Append(c); }
                    break;
            }
        }
        sb.Append('"');
    }

    static bool TryHex(string s, int start, out int code)
    {
        code = 0;
        for (int k = 0; k < 4; k++)
        {
            char h = s[start + k];
            int v;
            if (h >= '0' && h <= '9') { v = h - '0'; }
            else if (h >= 'a' && h <= 'f') { v = h - 'a' + 10; }
            else if (h >= 'A' && h <= 'F') { v = h - 'A' + 10; }
            else { return false; }
            code = (code << 4) | v;
        }
        return true;
    }

    static void NL(StringBuilder sb, int depth)
    {
        sb.Append('\n');
        sb.Append(' ', depth * 2);
    }

    // Tolerant JSON indenter (2 spaces). Optionally unescapes \uXXXX inside strings for display.
    public static string Indent(string s, bool unescape)
    {
        StringBuilder sb = new StringBuilder(s.Length + s.Length / 4);
        int depth = 0;
        int n = s.Length;
        int i = 0;
        while (i < n)
        {
            char c = s[i];
            if (c == '"')
            {
                sb.Append('"');
                i++;
                while (i < n)
                {
                    char d = s[i];
                    if (d == '\\' && i + 1 < n)
                    {
                        char e = s[i + 1];
                        int code;
                        if (unescape && e == 'u' && i + 5 < n && TryHex(s, i + 2, out code) && code >= 0x20 && code != '"' && code != '\\')
                        {
                            sb.Append((char)code);
                            i += 6;
                            continue;
                        }
                        sb.Append(d).Append(e);
                        i += 2;
                        continue;
                    }
                    sb.Append(d);
                    i++;
                    if (d == '"') { break; }
                }
                continue;
            }
            if (c == '{' || c == '[')
            {
                int j = i + 1;
                while (j < n && char.IsWhiteSpace(s[j])) { j++; }
                if (j < n && ((c == '{' && s[j] == '}') || (c == '[' && s[j] == ']')))
                {
                    sb.Append(c).Append(s[j]);
                    i = j + 1;
                    continue;
                }
                sb.Append(c);
                depth++;
                NL(sb, depth);
                i++;
                continue;
            }
            if (c == '}' || c == ']')
            {
                depth--;
                if (depth < 0) { depth = 0; }
                NL(sb, depth);
                sb.Append(c);
                i++;
                continue;
            }
            if (c == ',') { sb.Append(','); NL(sb, depth); i++; continue; }
            if (c == ':') { sb.Append(": "); i++; continue; }
            if (char.IsWhiteSpace(c))
            {
                if (depth == 0 && sb.Length > 0 && sb[sb.Length - 1] != '\n') { sb.Append('\n'); }
                i++;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString().TrimEnd();
    }
}
'@
    try { Add-Type -TypeDefinition $csharp -Language CSharp } catch { Write-Warning ('Native helper failed to compile: ' + $_.Exception.Message) }
}

$script:Jss = $null
try {
    if ($PSVersionTable.PSVersion.Major -ge 6) { throw 'JavaScriptSerializer is only used on Windows PowerShell' }
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $script:Jss = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $script:Jss.MaxJsonLength = [int]::MaxValue
    $script:Jss.RecursionLimit = 1000
} catch { $script:Jss = $null }
try { Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue } catch { }
$script:HasBrotli = [bool]('System.IO.Compression.BrotliStream' -as [type])
}
#endregion

#region Initialize-Constants
function Initialize-Constants {
$script:RxJwtKey = New-Object System.Text.RegularExpressions.Regex '(?:"(?<k>[^"\r\n]{1,40})"\s*:\s*")?(?<t>eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)'
$script:RxJwt = New-Object System.Text.RegularExpressions.Regex 'eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*'
$script:SecretNameList = 'client_secret|password|passwd|code|access_token|refresh_token|id_token|SAMLResponse|assertion|client_assertion|code_verifier'
$script:RxJsonSecret = New-Object System.Text.RegularExpressions.Regex ('(?i)(?<p>"(?<n>' + $script:SecretNameList + ')"\s*:\s*")(?<v>(?:[^"\\]|\\.)*)(?<q>")')
$script:RxInputTag = New-Object System.Text.RegularExpressions.Regex '(?is)<input\b[^>]*>'
$script:RxInputSecretName = New-Object System.Text.RegularExpressions.Regex ('(?is)\bname\s*=\s*["'']?(?:' + $script:SecretNameList + ')["'']?(?:[\s>/])')
$script:RxInputValue = New-Object System.Text.RegularExpressions.Regex '(?is)(?<p>\bvalue\s*=\s*["''])(?<v>[^"'']*)(?<q>["''])'
$script:RxUrlSecret = New-Object System.Text.RegularExpressions.Regex ('(?i)(?<p>[?&#;](?:' + $script:SecretNameList + ')=)(?<v>[^&#]*)')

$script:SecretParamNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($n in ($script:SecretNameList -split '\|')) { [void]$script:SecretParamNames.Add($n) }
$script:SecretHeaderNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($n in 'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'ocp-apim-subscription-key') { [void]$script:SecretHeaderNames.Add($n) }
$script:UrlHeaderNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($n in 'location', 'referer', 'content-location') { [void]$script:UrlHeaderNames.Add($n) }

$script:OAuthNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($n in 'client_id', 'scope', 'response_type', 'redirect_uri', 'grant_type', 'prompt', 'login_hint', 'domain_hint', 'state', 'nonce',
    'code_challenge', 'code_challenge_method', 'response_mode', 'resource', 'audience', 'claims', 'requested_token_use', 'client_assertion_type',
    'error', 'error_description', 'error_uri', 'error_subcode', 'username', 'code', 'client_secret', 'client_assertion', 'code_verifier',
    'assertion', 'password', 'refresh_token', 'access_token', 'id_token', 'token_type', 'expires_in') { [void]$script:OAuthNames.Add($n) }

$script:MaskEvaluator = [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-MaskedValue $m.Value }
$script:JsonSecretEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $v = $m.Groups['v'].Value
    if ($m.Groups['n'].Value -ieq 'code' -and $v.Length -lt 20) { return $m.Value }
    return $m.Groups['p'].Value + (Get-MaskedValue $v) + $m.Groups['q'].Value
}
$script:InputTagEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $tag = $m.Value
    if (-not $script:RxInputSecretName.IsMatch($tag)) { return $tag }
    return $script:RxInputValue.Replace($tag, [System.Text.RegularExpressions.MatchEvaluator] { param($x) $x.Groups['p'].Value + (Get-MaskedValue $x.Groups['v'].Value) + $x.Groups['q'].Value })
}
$script:UrlSecretEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    return $m.Groups['p'].Value + (Get-MaskedValue $m.Groups['v'].Value)
}
}
#endregion

#region Get-Prop
function Get-Prop {
    # Safe optional-property read for dictionaries (Dictionary/Hashtable) and PSObjects. Never throws under StrictMode.
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return ,$Default }
    if ($Obj -is [System.Collections.IDictionary]) {
        if (([System.Collections.IDictionary]$Obj).Contains($Name)) {
            $v = $Obj[$Name]
            if ($null -eq $v) { return ,$Default }
            return ,$v
        }
        return ,$Default
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -ne $p) {
        $v = $p.Value
        if ($null -eq $v) { return ,$Default }
        return ,$v
    }
    return ,$Default
}
#endregion

#region Get-List
function Get-List {
    # Always returns an object[] (JavaScriptSerializer gives object[] or ArrayList; ConvertFrom-Json gives object[]).
    param($Value)
    if ($null -eq $Value) { return ,@() }
    if ($Value -is [string] -or $Value -is [System.Collections.IDictionary]) { return ,@($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return ,@($Value) }
    return ,@($Value)
}
#endregion

#region Get-Num
function Get-Num {
    param($Value, [double]$Default = 0)
    if ($null -eq $Value) { return $Default }
    try { return [double]$Value } catch { return $Default }
}
#endregion

#region Add-Insight
function Add-Insight {
    param($List, [string]$Severity, [string]$Message)
    foreach ($i in $List) { if ($i['message'] -eq $Message) { return } }
    $List.Add([ordered]@{ severity = $Severity; message = $Message })
}
#endregion

#region ConvertFrom-JsonText
function ConvertFrom-JsonText {
    param([string]$Text)
    if ($null -ne $script:Jss) { return ,$script:Jss.DeserializeObject($Text) }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        try { return ,(ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 100) } catch { }
        return ,(ConvertFrom-Json -InputObject $Text -Depth 100)
    }
    return ,(ConvertFrom-Json -InputObject $Text)
}
#endregion

#region ConvertTo-HarDate
function ConvertTo-HarDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.DateTimeOffset]) { return $Value }
    if ($Value -is [System.DateTime]) {
        $d = $Value
        if ($d.Kind -eq [System.DateTimeKind]::Unspecified) { $d = [System.DateTime]::SpecifyKind($d, [System.DateTimeKind]::Utc) }
        return [System.DateTimeOffset]$d
    }
    $dto = [System.DateTimeOffset]::MinValue
    if ([System.DateTimeOffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $dto }
    return $null
}
#endregion

#region Format-IsoUtc
function Format-IsoUtc {
    param([System.DateTimeOffset]$Date)
    return $Date.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}
#endregion

#region ConvertFrom-UrlEncoded
function ConvertFrom-UrlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text.Replace('+', ' ')
    try { return [System.Uri]::UnescapeDataString($t) } catch { return $t }
}
#endregion

#region Get-MimeBase
function Get-MimeBase {
    param([string]$ContentType)
    if ([string]::IsNullOrWhiteSpace($ContentType)) { return '' }
    return ($ContentType.Split(';')[0]).Trim().ToLowerInvariant()
}
#endregion

#region Get-Charset
function Get-Charset {
    param([string]$ContentType)
    if ($ContentType -and $ContentType -match '(?i)charset\s*=\s*"?([\w\-]+)') { return $Matches[1] }
    return ''
}
#endregion

#region Read-Pairs
function Read-Pairs {
    param($Items)
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($i in (Get-List $Items)) {
        if ($null -eq $i) { continue }
        $n = [string](Get-Prop $i 'name' '')
        $v = [string](Get-Prop $i 'value' '')
        $list.Add([ordered]@{ name = $n; value = $v })
    }
    return ,$list
}
#endregion

#region Get-HeaderValue
function Get-HeaderValue {
    param($List, [string]$Name)
    foreach ($h in $List) { if ([string]::Equals($h['name'], $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $h['value'] } }
    return $null
}
#endregion

#region Get-HeaderValues
function Get-HeaderValues {
    param($List, [string]$Name)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($h in $List) { if ([string]::Equals($h['name'], $Name, [System.StringComparison]::OrdinalIgnoreCase)) { $out.Add([string]$h['value']) } }
    return ,$out
}
#endregion

#region Write-Stage
function Write-Stage {
    param($Stopwatch, [string]$Message)
    Write-Verbose ('[{0,8:N0} ms] {1}' -f $Stopwatch.ElapsedMilliseconds, $Message)
}
#endregion

#region Get-MaskedValue
function Get-MaskedValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value.Length -le 8) { return '****' }
    return $Value.Substring(0, 4) + '****' + $Value.Substring($Value.Length - 4)
}
#endregion

#region Protect-Secrets
function Protect-Secrets {
    # Mode: Param (name/value), Header (name/value), Text (free text), Url, Form (urlencoded body)
    param(
        [ValidateSet('Param', 'Header', 'Text', 'Url', 'Form')][string]$Mode = 'Param',
        [string]$Name,
        [string]$Value
    )
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    switch ($Mode) {
        'Param' {
            if ($script:SecretParamNames.Contains($Name)) { return Get-MaskedValue $Value }
            return $script:RxJwt.Replace($Value, $script:MaskEvaluator)
        }
        'Header' {
            $n = $Name.ToLowerInvariant()
            if ($n -eq 'cookie') {
                $parts = $Value.Split(';')
                $sb = New-Object System.Text.StringBuilder
                for ($i = 0; $i -lt $parts.Length; $i++) {
                    $p = $parts[$i]
                    $eq = $p.IndexOf('=')
                    if ($i -gt 0) { [void]$sb.Append(';') }
                    if ($eq -ge 0) { [void]$sb.Append($p.Substring(0, $eq + 1)).Append((Get-MaskedValue $p.Substring($eq + 1).Trim())) } else { [void]$sb.Append($p) }
                }
                return $sb.ToString()
            }
            if ($n -eq 'set-cookie') {
                $semi = $Value.IndexOf(';')
                $first = $Value
                $rest = ''
                if ($semi -ge 0) { $first = $Value.Substring(0, $semi); $rest = $Value.Substring($semi) }
                $eq = $first.IndexOf('=')
                if ($eq -ge 0) { return $first.Substring(0, $eq + 1) + (Get-MaskedValue $first.Substring($eq + 1)) + $rest }
                return $Value
            }
            if ($n -eq 'authorization' -or $n -eq 'proxy-authorization') {
                if ($Value -match '^\s*(Bearer|Basic|Negotiate|NTLM|Digest|Kerberos)\s+(.+)$') { return $Matches[1] + ' ' + (Get-MaskedValue $Matches[2].Trim()) }
                return Get-MaskedValue $Value
            }
            if ($script:SecretHeaderNames.Contains($n)) { return Get-MaskedValue $Value }
            if ($script:UrlHeaderNames.Contains($n)) { return Protect-Secrets -Mode Url -Value $Value }
            return $script:RxJwt.Replace($Value, $script:MaskEvaluator)
        }
        'Url' {
            $r = $script:RxUrlSecret.Replace($Value, $script:UrlSecretEvaluator)
            return $script:RxJwt.Replace($r, $script:MaskEvaluator)
        }
        'Form' {
            $sb = New-Object System.Text.StringBuilder
            $pairs = $Value.Split('&')
            for ($i = 0; $i -lt $pairs.Length; $i++) {
                $p = $pairs[$i]
                if ($i -gt 0) { [void]$sb.Append('&') }
                $eq = $p.IndexOf('=')
                if ($eq -lt 0) { [void]$sb.Append($p); continue }
                $nm = ConvertFrom-UrlEncoded $p.Substring(0, $eq)
                if ($script:SecretParamNames.Contains($nm)) { [void]$sb.Append($p.Substring(0, $eq + 1)).Append((Get-MaskedValue $p.Substring($eq + 1))) } else { [void]$sb.Append($p) }
            }
            return $script:RxJwt.Replace($sb.ToString(), $script:MaskEvaluator)
        }
        'Text' {
            $r = $script:RxJsonSecret.Replace($Value, $script:JsonSecretEvaluator)
            if ($r.IndexOf('<input', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $r = $script:RxInputTag.Replace($r, $script:InputTagEvaluator) }
            return $script:RxJwt.Replace($r, $script:MaskEvaluator)
        }
    }
}
#endregion

#region Protect-PairList
function Protect-PairList {
    param($List, [string]$Mode = 'Param')
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $List) {
        $v = $p['value']
        if ($Mode -eq 'Header') { $v = Protect-Secrets -Mode Header -Name $p['name'] -Value $v } else { $v = Protect-Secrets -Mode Param -Name $p['name'] -Value $v }
        $c = [ordered]@{}
        foreach ($k in $p.Keys) { $c[$k] = $p[$k] }
        $c['value'] = $v
        $out.Add($c)
    }
    return ,$out
}
#endregion

#region ConvertFrom-Base64Safe
function ConvertFrom-Base64Safe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,(New-Object byte[] 0) }
    $s = $Text.Trim().Replace(' ', '+').Replace("`r", '').Replace("`n", '').Replace('-', '+').Replace('_', '/').TrimEnd('=')
    switch ($s.Length % 4) {
        1 { throw 'Invalid base64 length' }
        2 { $s = $s + '==' }
        3 { $s = $s + '=' }
    }
    return ,[System.Convert]::FromBase64String($s)
}
#endregion

#region Read-StreamAll
function Read-StreamAll {
    param([System.IO.Stream]$Stream)
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 81920
    while (($n = $Stream.Read($buf, 0, $buf.Length)) -gt 0) {
        $ms.Write($buf, 0, $n)
        if ($ms.Length -gt 268435456) { throw 'Decompressed size exceeds the 256 MB safety limit' }
    }
    return ,$ms.ToArray()
}
#endregion

#region Expand-Compressed
function Expand-Compressed {
    # Returns @{ Bytes; Method; Message }. Detects gzip by magic bytes; deflate/brotli by Content-Encoding.
    param([byte[]]$Bytes, [string]$ContentEncoding)
    $ce = ''
    if ($ContentEncoding) { $ce = $ContentEncoding.ToLowerInvariant() }
    $res = @{ Bytes = $Bytes; Method = 'none'; Message = '' }
    if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return $res }
    try {
        if ($Bytes[0] -eq 0x1F -and $Bytes[1] -eq 0x8B) {
            $ms = New-Object System.IO.MemoryStream (, $Bytes)
            $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $res.Bytes = Read-StreamAll $gz
            $res.Method = 'gzip'
            return $res
        }
        $head = [Math]::Min(64, $Bytes.Length)
        $looksBinary = $false
        for ($i = 0; $i -lt $head; $i++) { $b = $Bytes[$i]; if ($b -lt 9 -or ($b -gt 13 -and $b -lt 32) -or $b -gt 127) { $looksBinary = $true; break } }
        if ($ce -match '\bdeflate\b' -and $looksBinary) {
            $skip = 0
            if (($Bytes[0] -band 0x0F) -eq 8 -and ((($Bytes[0] * 256) + $Bytes[1]) % 31) -eq 0) { $skip = 2 }
            try {
                $ms = New-Object System.IO.MemoryStream($Bytes, $skip, ($Bytes.Length - $skip))
                $df = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
                $res.Bytes = Read-StreamAll $df
                $res.Method = 'deflate'
            } catch {
                if ($skip -eq 2) {
                    $ms = New-Object System.IO.MemoryStream (, $Bytes)
                    $df = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
                    $res.Bytes = Read-StreamAll $df
                    $res.Method = 'deflate'
                } else { throw }
            }
            return $res
        }
        if ($ce -match '\bbr\b' -and $looksBinary) {
            if ($script:HasBrotli) {
                $ms = New-Object System.IO.MemoryStream (, $Bytes)
                $br = New-Object System.IO.Compression.BrotliStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
                $res.Bytes = Read-StreamAll $br
                $res.Method = 'brotli'
            } else {
                $res.Message = 'Body is Brotli-compressed; Brotli decompression needs PowerShell 7+ (shown as binary).'
            }
            return $res
        }
    } catch {
        $res.Bytes = $Bytes
        $res.Method = 'none'
        $res.Message = 'Decompression failed: ' + $_.Exception.Message
    }
    return $res
}
#endregion

#region Test-TextMime
function Test-TextMime {
    param([string]$Mime)
    return ($Mime -match '^(text/|multipart/)' -or $Mime -match 'json|xml|javascript|ecmascript|html|svg|x-www-form-urlencoded|css|yaml|csv|graphql|x-sh$')
}
#endregion

#region Test-BinaryBytes
function Test-BinaryBytes {
    param([byte[]]$Bytes, [string]$Mime)
    if (Test-TextMime $Mime) { return $false }
    if ($Mime -match '^(image/|audio/|video/|font/)' -or $Mime -match '^application/(pdf|zip|gzip|x-gzip|wasm|x-font|vnd\.ms-fontobject|x-protobuf|protobuf|grpc|x-tar|x-7z|vnd\.)') { return $true }
    $n = [Math]::Min(512, $Bytes.Length)
    $odd = 0
    for ($i = 0; $i -lt $n; $i++) {
        $b = $Bytes[$i]
        if ($b -eq 0) { return $true }
        if ($b -lt 9 -or ($b -gt 13 -and $b -lt 32)) { $odd++ }
    }
    return ($n -gt 0 -and ($odd * 10) -gt $n)
}
#endregion

#region Convert-BytesToText
function Convert-BytesToText {
    param([byte[]]$Bytes, [string]$Charset)
    $enc = [System.Text.Encoding]::UTF8
    if ($Charset) { try { $enc = [System.Text.Encoding]::GetEncoding($Charset) } catch { $enc = [System.Text.Encoding]::UTF8 } }
    return $enc.GetString($Bytes).TrimStart([char]0xFEFF)
}
#endregion

#region Get-QueryParameters
function Get-QueryParameters {
    # D3/D4: name/value table, URL-decoded, repeated keys kept.
    param([string]$QueryString)
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrEmpty($QueryString)) { return ,$list }
    $q = $QueryString
    $h = $q.IndexOf('#')
    if ($h -ge 0) { $q = $q.Substring(0, $h) }
    $qi = $q.IndexOf('?')
    if ($qi -ge 0) { $q = $q.Substring($qi + 1) }
    foreach ($pair in $q.Split('&')) {
        if ($pair.Length -eq 0) { continue }
        $eq = $pair.IndexOf('=')
        if ($eq -ge 0) {
            $list.Add([ordered]@{ name = (ConvertFrom-UrlEncoded $pair.Substring(0, $eq)); value = (ConvertFrom-UrlEncoded $pair.Substring($eq + 1)) })
        } else {
            $list.Add([ordered]@{ name = (ConvertFrom-UrlEncoded $pair); value = '' })
        }
    }
    return ,$list
}
#endregion

#region Read-XmlDoc
function Read-XmlDoc {
    param([string]$Xml)
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $sr = New-Object System.IO.StringReader($Xml.Trim())
    $xr = [System.Xml.XmlReader]::Create($sr, $settings)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($xr)
    } finally { $xr.Close(); $sr.Dispose() }
    return ,$doc
}
#endregion

#region Format-XmlDoc
function Format-XmlDoc {
    param($Doc)
    $ws = New-Object System.Xml.XmlWriterSettings
    $ws.Indent = $true
    $ws.IndentChars = '  '
    $ws.OmitXmlDeclaration = $true
    $strw = New-Object System.IO.StringWriter
    $xw = [System.Xml.XmlWriter]::Create($strw, $ws)
    try { $Doc.Save($xw) } finally { $xw.Close() }
    return $strw.ToString()
}
#endregion

#region Format-Xml
function Format-Xml {
    param([string]$Xml)
    return Format-XmlDoc (Read-XmlDoc $Xml)
}
#endregion

#region Format-Json
function Format-Json {
    param([string]$Json)
    return [HarFmt]::Indent($Json, $true)
}
#endregion

#region Read-Multipart
function Read-Multipart {
    # D5: split by boundary; text parts shown, files summarised.
    param([string]$Text, [string]$Boundary, [bool]$Redact)
    $parts = New-Object 'System.Collections.Generic.List[object]'
    if (-not $Boundary) { return ,$parts }
    $chunks = $Text.Split([string[]]@('--' + $Boundary), [System.StringSplitOptions]::None)
    for ($i = 1; $i -lt $chunks.Length; $i++) {
        $c = $chunks[$i]
        if ($c.StartsWith('--')) { break }
        if ($c.StartsWith("`r`n")) { $c = $c.Substring(2) } elseif ($c.StartsWith("`n")) { $c = $c.Substring(1) }
        $sepLen = 4
        $idx = $c.IndexOf("`r`n`r`n")
        if ($idx -lt 0) { $idx = $c.IndexOf("`n`n"); $sepLen = 2 }
        $headerText = $c
        $body = ''
        if ($idx -ge 0) { $headerText = $c.Substring(0, $idx); $body = $c.Substring($idx + $sepLen) }
        if ($body.EndsWith("`r`n")) { $body = $body.Substring(0, $body.Length - 2) } elseif ($body.EndsWith("`n")) { $body = $body.Substring(0, $body.Length - 1) }
        $hdrs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($line in ($headerText -split "\r?\n")) {
            $ci = $line.IndexOf(':')
            if ($ci -gt 0) { $hdrs.Add([ordered]@{ name = $line.Substring(0, $ci).Trim(); value = $line.Substring($ci + 1).Trim() }) }
        }
        $disp = [string](Get-HeaderValue $hdrs 'content-disposition')
        $pname = ''
        $fname = ''
        if ($disp -match '(?i)(?<![\w])name\s*=\s*"([^"]*)"') { $pname = $Matches[1] }
        if ($disp -match '(?i)filename\s*=\s*"([^"]*)"') { $fname = $Matches[1] }
        $ptype = [string](Get-HeaderValue $hdrs 'content-type')
        $size = [System.Text.Encoding]::UTF8.GetByteCount($body)
        $ptext = ''
        if (-not $fname) {
            $ptext = $body
            if ($ptext.Length -gt $script:MaxBodyBytes) { $ptext = $ptext.Substring(0, [int]$script:MaxBodyBytes) }
            if ($Redact -and $script:SecretParamNames.Contains($pname)) { $ptext = Get-MaskedValue $ptext }
            elseif ($Redact) { $ptext = Protect-Secrets -Mode Text -Value $ptext }
        }
        $outHdrs = if ($Redact) { Protect-PairList $hdrs 'Header' } else { $hdrs }
        $parts.Add([ordered]@{ headers = $outHdrs; name = $pname; filename = $fname; contentType = $ptype; size = $size; text = $ptext })
    }
    return ,$parts
}
#endregion

#region Get-TextFormat
function Get-TextFormat {
    param([string]$Mime, [string]$Text)
    if ($Mime -match 'x-www-form-urlencoded') { return 'form' }
    if ($Mime -match '^multipart/') { return 'multipart' }
    if ($Mime -match 'json') { return 'json' }
    if ($Mime -match 'html') { return 'html' }
    if ($Mime -match 'xml') { return 'xml' }
    if (-not $Mime -or $Mime -eq 'text/plain' -or $Mime -eq 'application/octet-stream') {
        $t = $Text.TrimStart()
        if ($t.Length -gt 1) {
            $last = $Text.TrimEnd()
            if (($t[0] -eq '{' -and $last.EndsWith('}')) -or ($t[0] -eq '[' -and $last.EndsWith(']'))) { return 'json' }
            if ($t.StartsWith('<?xml')) { return 'xml' }
            if ($t -match '(?i)^<(!doctype html|html)') { return 'html' }
        }
    }
    return 'text'
}
#endregion

#region Expand-Body
function Expand-Body {
    # Decodes one request/response body. Returns @{ Model; Text; Params } where Text is the original (unredacted) decoded text.
    param(
        $Text, [bool]$IsBase64, [string]$ContentType, [string]$ContentEncoding,
        [double]$DeclaredSize, [double]$CompressedSize, $Insights, [string]$Side, [bool]$Redact
    )
    $cap = $script:MaxBodyBytes
    $mime = Get-MimeBase $ContentType
    $charset = Get-Charset $ContentType
    if ($CompressedSize -lt 0) { $CompressedSize = 0 }
    $model = [ordered]@{
        raw = ''; decoded = ''; format = 'empty'; size = 0; originalSize = 0; compressedSize = [int64]$CompressedSize
        encoding = 'none'; truncated = $false; b64 = ''
    }
    $out = @{ Model = $model; Text = ''; Params = $null }

    if ($null -eq $Text -or ([string]$Text).Length -eq 0) {
        if ($DeclaredSize -gt 0) {
            $model.size = [int64]$DeclaredSize
            $model.originalSize = [int64]$DeclaredSize
            $model.note = 'Body not captured by the browser (content stripped or not available)'
            Add-Insight $Insights 'info' ("{0} body not captured by the browser ({1:N0} bytes expected)." -f $Side, $DeclaredSize)
        } else {
            $model.note = 'No body'
        }
        return $out
    }

    $Text = [string]$Text
    $bytes = $null
    $str = $null
    $isBinary = $false
    $rawB64 = $null

    if ($IsBase64) {
        $model.encoding = 'base64'
        $rawB64 = $Text
        try { $bytes = ConvertFrom-Base64Safe $Text } catch {
            $bytes = $null
            Add-Insight $Insights 'warning' ("Base64 decoding of the $Side body failed: " + $_.Exception.Message)
        }
        if ($null -eq $bytes) {
            $model.encoding = 'none'
            $str = $Text
        } else {
            try {
                $dec = Expand-Compressed $bytes $ContentEncoding
                if ($dec.Method -ne 'none') {
                    if ($model.compressedSize -le 0) { $model.compressedSize = [int64]$bytes.Length }
                    $bytes = $dec.Bytes
                    Add-Insight $Insights 'info' ("$Side body was $($dec.Method)-compressed and has been decompressed.")
                } elseif ($dec.Message) {
                    Add-Insight $Insights 'warning' ("$Side body: " + $dec.Message)
                }
            } catch { Add-Insight $Insights 'warning' ("Decompression of the $Side body failed: " + $_.Exception.Message) }
            $isBinary = Test-BinaryBytes $bytes $mime
            if (-not $isBinary) {
                try { $str = Convert-BytesToText $bytes $charset } catch { $str = Convert-BytesToText $bytes '' }
            }
        }
    } else {
        $str = $Text
    }

    if ($isBinary) {
        $model.format = 'binary'
        $model.size = [int64]$bytes.Length
        $model.originalSize = [int64]$bytes.Length
        $model.decoded = ('[Binary data: {0:N0} bytes, {1}]' -f $bytes.Length, $(if ($mime) { $mime } else { 'unknown type' }))
        if ($bytes.Length -le $cap) { $model.b64 = [System.Convert]::ToBase64String($bytes) } else { $model.truncated = $true; Add-Insight $Insights 'info' ("$Side binary body ({0:N0} bytes) exceeds the 5 MB body limit; not embedded." -f $bytes.Length) }
        return $out
    }

    if ($null -ne $bytes) { $model.size = [int64]$bytes.Length } else { $model.size = [int64][System.Text.Encoding]::UTF8.GetByteCount($str) }
    $model.originalSize = $model.size
    $out.Text = $str

    # Images stored as text (e.g. SVG) still get a b64 copy for previews.
    if ($null -ne $bytes -and $mime -like 'image/*' -and $bytes.Length -le $cap) { $model.b64 = [System.Convert]::ToBase64String($bytes) }

    $truncated = $false
    $work = $str
    if ($work.Length -gt $cap) {
        $work = $work.Substring(0, [int]$cap)
        $truncated = $true
        $model.truncated = $true
        Add-Insight $Insights 'info' ("$Side body truncated to {0:N0} KB (original size {1:N0} bytes)." -f ($cap / 1024), $model.size)
    }

    $fmt = Get-TextFormat $mime $work
    $model.format = $fmt
    $rawOut = $work
    if ($IsBase64 -and $null -ne $rawB64 -and -not $Redact) {
        $rawOut = $rawB64
        if ($rawOut.Length -gt $cap) { $rawOut = $rawOut.Substring(0, [int]$cap) }
    }

    try {
        switch ($fmt) {
            'form' {
                $rawParams = Get-QueryParameters $str
                $out.Params = $rawParams
                $mp = if ($Redact) { Protect-PairList $rawParams 'Param' } else { $rawParams }
                $model.params = $mp
                if ($Redact) { $work = Protect-Secrets -Mode Form -Value $work; $rawOut = $work }
                $lines = New-Object System.Text.StringBuilder
                foreach ($p in $mp) { [void]$lines.Append($p['name']).Append(' = ').Append($p['value']).Append("`n") }
                $model.decoded = $lines.ToString().TrimEnd()
            }
            'multipart' {
                $boundary = ''
                if ($ContentType -match '(?i)boundary\s*=\s*"?([^";]+)"?') { $boundary = $Matches[1].Trim() }
                $parts = Read-Multipart $work $boundary $Redact
                $model.parts = $parts
                $sbd = New-Object System.Text.StringBuilder
                foreach ($p in $parts) {
                    [void]$sbd.AppendFormat('--- {0}', $p['name'])
                    if ($p['filename']) { [void]$sbd.AppendFormat(' (file: {0}, {1}, {2:N0} bytes)', $p['filename'], $p['contentType'], $p['size']) }
                    [void]$sbd.Append(" ---`n")
                    if ($p['filename']) { [void]$sbd.Append("[file content not shown]`n") } else { [void]$sbd.Append($p['text']).Append("`n") }
                }
                $model.decoded = $sbd.ToString().TrimEnd()
                if ($Redact) {
                    $rb = New-Object System.Text.StringBuilder
                    foreach ($p in $parts) {
                        [void]$rb.Append('--').Append($boundary).Append("`r`n")
                        foreach ($h in $p['headers']) { [void]$rb.Append($h['name']).Append(': ').Append($h['value']).Append("`r`n") }
                        [void]$rb.Append("`r`n").Append($p['text']).Append("`r`n")
                    }
                    [void]$rb.Append('--').Append($boundary).Append('--')
                    $rawOut = $rb.ToString()
                }
            }
            'json' {
                if ($Redact) { $work = Protect-Secrets -Mode Text -Value $work; $rawOut = $work }
                try { $model.decoded = Format-Json $work } catch { $model.decoded = $work; Add-Insight $Insights 'warning' ("JSON pretty-print of the $Side body failed: " + $_.Exception.Message) }
            }
            'xml' {
                if ($Redact) { $work = Protect-Secrets -Mode Text -Value $work; $rawOut = $work }
                try {
                    if ($truncated) { $model.decoded = $work } else { $model.decoded = Format-Xml $work }
                } catch {
                    $model.decoded = $work
                    Add-Insight $Insights 'warning' ("XML pretty-print of the $Side body failed: " + $_.Exception.Message)
                }
            }
            default {
                if ($Redact) { $work = Protect-Secrets -Mode Text -Value $work; $rawOut = $work }
                $model.decoded = $work
            }
        }
    } catch {
        Add-Insight $Insights 'warning' ("Decoding of the $Side body ($fmt) failed: " + $_.Exception.Message)
        if ($Redact) { $work = Protect-Secrets -Mode Text -Value $work; $rawOut = $work }
        $model.decoded = $work
    }
    $model.raw = $rawOut
    return $out
}
#endregion

#region ConvertFrom-Jwt
function ConvertFrom-Jwt {
    # D8: decode header/payload only; the signature is never decoded. Claims are withheld when redacting.
    param([string]$Token, [string]$Where)
    try {
        $parts = $Token.Split('.')
        if ($parts.Length -lt 2) { return $null }
        $h = ConvertFrom-JsonText ([System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Safe $parts[0])))
        $p = ConvertFrom-JsonText ([System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Safe $parts[1])))
        if ($h -isnot [System.Collections.IDictionary] -or $p -isnot [System.Collections.IDictionary]) { return $null }
        $nowSec = ([System.DateTime]::UtcNow - $script:Epoch).TotalSeconds
        $exp = Get-Prop $p 'exp'
        $iat = Get-Prop $p 'iat'
        $nbf = Get-Prop $p 'nbf'
        $toIso = {
            param($v)
            if ($null -eq $v) { return '' }
            try { return (Format-IsoUtc ([System.DateTimeOffset]$script:Epoch.AddSeconds([double]$v))) } catch { return '' }
        }
        $expired = $false
        if ($null -ne $exp) { try { $expired = ([double]$exp -lt $nowSec) } catch { $expired = $false } }
        $jwt = [ordered]@{
            where = $Where
            token = $(if ($script:Redact) { Get-MaskedValue $Token } else { $Token })
            header = $(if ($script:Redact) { [ordered]@{} } else { $h })
            payload = $(if ($script:Redact) { [ordered]@{} } else { $p })
            expired = $expired
            expiresAt = (& $toIso $exp)
            issuedAt = (& $toIso $iat)
            notBefore = (& $toIso $nbf)
        }
        if ($script:Redact) { $jwt['redacted'] = $true }
        return $jwt
    } catch { return $null }
}
#endregion

#region Add-JwtsFromText
function Add-JwtsFromText {
    param([string]$Text, [string]$Where, $List, $Seen)
    if ([string]::IsNullOrEmpty($Text) -or $Text.IndexOf('eyJ', [System.StringComparison]::Ordinal) -lt 0) { return }
    if ($Text.Length -gt 8388608) { $Text = $Text.Substring(0, 8388608) }
    foreach ($m in $script:RxJwtKey.Matches($Text)) {
        if ($List.Count -ge 20) { break }
        $tok = $m.Groups['t'].Value
        $w = $Where
        if ($m.Groups['k'].Success) { $w = $Where + ' (' + $m.Groups['k'].Value + ')' }
        if (-not $Seen.Add($w + '|' + $tok)) { continue }
        $j = ConvertFrom-Jwt $tok $w
        if ($null -ne $j) { $List.Add($j) }
    }
}
#endregion

#region Get-XmlText
function Get-XmlText {
    param($Doc, [string]$LocalName)
    $n = $Doc.SelectSingleNode("//*[local-name()='$LocalName']")
    if ($null -eq $n) { return '' }
    return $n.InnerText.Trim()
}
#endregion

#region ConvertFrom-Saml
function ConvertFrom-Saml {
    # D9: SAMLRequest (redirect binding: urldecode + base64 + raw inflate) / SAMLResponse (base64); POST bindings auto-detected.
    param([string]$Value, [string]$Kind, [string]$Where)
    try {
        $v = $Value
        if ($v -match '%[0-9A-Fa-f]{2}') { $v = [System.Uri]::UnescapeDataString($v) }
        $bytes = ConvertFrom-Base64Safe $v
        $start = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
        $xmlText = $null
        $k = $start
        while ($k -lt $bytes.Length -and ($bytes[$k] -eq 32 -or $bytes[$k] -eq 9 -or $bytes[$k] -eq 10 -or $bytes[$k] -eq 13)) { $k++ }
        if ($k -lt $bytes.Length -and $bytes[$k] -eq 60) {
            $xmlText = [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
        } else {
            $ms = New-Object System.IO.MemoryStream (, $bytes)
            $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $xmlText = [System.Text.Encoding]::UTF8.GetString((Read-StreamAll $ds))
        }
        $saml = [ordered]@{
            kind = $Kind; where = $Where; xml = ''; issuer = ''; nameId = ''; audience = ''
            notBefore = ''; notOnOrAfter = ''; statusCode = ''; destination = ''
            attributes = (New-Object 'System.Collections.Generic.List[object]')
        }
        $doc = $null
        try { $doc = Read-XmlDoc $xmlText } catch { $saml.xml = $(if ($script:Redact) { '<!-- SAML content redacted (-RedactSecrets) -->' } else { $xmlText }) }
        if ($null -ne $doc) {
            $pretty = Format-XmlDoc $doc
            $saml.issuer = Get-XmlText $doc 'Issuer'
            $saml.nameId = Get-XmlText $doc 'NameID'
            $auds = New-Object 'System.Collections.Generic.List[string]'
            foreach ($a in $doc.SelectNodes("//*[local-name()='Audience']")) { $auds.Add($a.InnerText.Trim()) }
            $saml.audience = ($auds -join ', ')
            $cond = $doc.SelectSingleNode("//*[local-name()='Conditions']")
            if ($null -ne $cond) { $saml.notBefore = $cond.GetAttribute('NotBefore'); $saml.notOnOrAfter = $cond.GetAttribute('NotOnOrAfter') }
            if (-not $saml.notOnOrAfter) {
                $scd = $doc.SelectSingleNode("//*[local-name()='SubjectConfirmationData']")
                if ($null -ne $scd) { $saml.notOnOrAfter = $scd.GetAttribute('NotOnOrAfter') }
            }
            $sc = $doc.SelectSingleNode("//*[local-name()='StatusCode']")
            if ($null -ne $sc) { $saml.statusCode = $sc.GetAttribute('Value') }
            if ($null -ne $doc.DocumentElement) { $saml.destination = $doc.DocumentElement.GetAttribute('Destination') }
            foreach ($attr in $doc.SelectNodes("//*[local-name()='Attribute']")) {
                $vals = New-Object 'System.Collections.Generic.List[string]'
                foreach ($av in $attr.SelectNodes("*[local-name()='AttributeValue']")) { $vals.Add($av.InnerText.Trim()) }
                $saml.attributes.Add([ordered]@{ name = $attr.GetAttribute('Name'); value = ($vals -join ', ') })
            }
            if ($script:Redact) {
                $saml.xml = '<!-- SAML content redacted (-RedactSecrets) -->'
                $saml.nameId = Get-MaskedValue $saml.nameId
                foreach ($a in $saml.attributes) { $a['value'] = Get-MaskedValue $a['value'] }
            } else {
                $saml.xml = $pretty
            }
        }
        return $saml
    } catch {
        return $null
    }
}
#endregion

#region Get-HtmlSamlInputs
function Get-HtmlSamlInputs {
    # SAML POST-binding auto-submit forms inside HTML bodies.
    param([string]$Html)
    $res = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrEmpty($Html) -or $Html.IndexOf('SAML', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return ,$res }
    foreach ($t in $script:RxInputTag.Matches($Html)) {
        $tag = $t.Value
        if ($tag -match '(?i)\bname\s*=\s*["'']?(SAMLRequest|SAMLResponse)["'']?') {
            $nm = $Matches[1]
            if ($tag -match '(?i)\bvalue\s*=\s*["'']([^"'']*)["'']') {
                $res.Add(@{ Name = $nm; Value = [System.Net.WebUtility]::HtmlDecode($Matches[1]) })
            }
        }
    }
    return ,$res
}
#endregion

#region Get-CorrelationIds
function Get-CorrelationIds {
    param($ReqHeaders, $RespHeaders)
    $names = 'x-ms-request-id', 'x-ms-correlation-id', 'client-request-id', 'request-id', 'x-ms-ags-diagnostic', 'traceparent',
        'x-correlation-id', 'date', 'x-request-id', 'x-ms-client-request-id', 'ms-cv', 'sprequestguid'
    $c = [ordered]@{}
    foreach ($n in $names) {
        $v = Get-HeaderValue $RespHeaders $n
        if ([string]::IsNullOrEmpty($v)) { $v = Get-HeaderValue $ReqHeaders $n }
        if (-not [string]::IsNullOrEmpty($v)) { $c[$n] = $v }
    }
    return $c
}
#endregion

#region Parse-SetCookie
function Parse-SetCookie {
    param([string]$Header)
    $parts = $Header.Split(';')
    $first = $parts[0]
    $eq = $first.IndexOf('=')
    $c = [ordered]@{ name = ''; value = ''; domain = ''; path = ''; expires = ''; secure = $false; httpOnly = $false; sameSite = '' }
    if ($eq -ge 0) { $c.name = $first.Substring(0, $eq).Trim(); $c.value = $first.Substring($eq + 1).Trim() } else { $c.name = $first.Trim() }
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $a = $parts[$i].Trim()
        $e = $a.IndexOf('=')
        $k = $a
        $val = ''
        if ($e -ge 0) { $k = $a.Substring(0, $e).Trim(); $val = $a.Substring($e + 1).Trim() }
        switch ($k.ToLowerInvariant()) {
            'domain' { $c.domain = $val }
            'path' { $c.path = $val }
            'expires' { $c.expires = $val }
            'max-age' { $c.maxAge = $val }
            'secure' { $c.secure = $true }
            'httponly' { $c.httpOnly = $true }
            'samesite' { $c.sameSite = $val }
        }
    }
    return $c
}
#endregion

#region Get-ResourceType
function Get-ResourceType {
    param([string]$Declared, [string]$Mime, [string]$Scheme, [string]$Path)
    $d = ''
    if ($Declared) { $d = $Declared.ToLowerInvariant() }
    if ($Scheme -eq 'ws' -or $Scheme -eq 'wss') { return 'websocket' }
    if ($d -in 'document', 'script', 'stylesheet', 'xhr', 'fetch', 'image', 'font', 'media', 'websocket') { return $d }
    if ($d -eq 'css') { return 'stylesheet' }
    $ext = ''
    if ($Path) { $ext = [System.IO.Path]::GetExtension($Path).TrimStart('.').ToLowerInvariant() }
    if ($Mime -like 'image/*' -or $ext -in 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'bmp', 'avif') { return 'image' }
    if ($Mime -like 'font/*' -or $Mime -match 'font' -or $ext -in 'woff', 'woff2', 'ttf', 'otf', 'eot') { return 'font' }
    if ($Mime -eq 'text/css' -or $ext -eq 'css') { return 'stylesheet' }
    if ($Mime -match 'javascript|ecmascript' -or $ext -in 'js', 'mjs') { return 'script' }
    if ($Mime -like 'audio/*' -or $Mime -like 'video/*' -or $ext -in 'mp3', 'mp4', 'webm', 'ogg', 'wav', 'm4a') { return 'media' }
    if ($Mime -match 'html') { return 'document' }
    if ($d -in 'preflight', 'ping', 'other', 'manifest', 'texttrack', 'eventsource', 'cspviolationreport', 'signedexchange', 'prefetch') { return 'other' }
    if ($Mime -match 'json|xml') { return 'xhr' }
    return 'other'
}
#endregion

#region Get-EntryInsights
function Get-EntryInsights {
    param($Entry, $ReqHeaders, $RespHeaders, $Jwts, $Saml, $SearchTexts, $Insights)
    $status = [int]$Entry['status']
    $url = [string]$Entry['url']
    # HTTP / network failures
    if ($status -ge 500) { Add-Insight $Insights 'error' ("HTTP $status $($Entry['statusText'])".Trim()) }
    elseif ($status -ge 400) {
        $sev = 'error'
        if ($status -eq 404 -or $status -eq 410) { $sev = 'warning' }
        Add-Insight $Insights $sev ("HTTP $status $($Entry['statusText'])".Trim())
    }
    $err = [string]$Entry['error']
    if ($status -eq 0 -or $err) {
        $msg = 'Request failed or was blocked'
        if ($err) { $msg = $msg + ': ' + $err } else { $msg = $msg + ' (status 0, no response received)' }
        Add-Insight $Insights 'error' $msg
    }
    if ($err -match '(?i)ERR_CERT|ERR_SSL|ERR_BAD_SSL|ERR_TLS|SSL|certificate|TLS') { Add-Insight $Insights 'error' ('Certificate / TLS error: ' + $err) }

    # AADSTS codes
    $rx = New-Object System.Text.RegularExpressions.Regex '(AADSTS\d{4,6})\s*[:\-]?\s*(.{0,300}?)(?=\\r\\n|\\n|\\r|"|\r|\n|Trace ID|$)'
    $seenAad = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($t in $SearchTexts) {
        if ([string]::IsNullOrEmpty($t) -or $t.IndexOf('AADSTS', [System.StringComparison]::Ordinal) -lt 0) { continue }
        foreach ($m in $rx.Matches($t)) {
            $code = $m.Groups[1].Value
            if ($seenAad.Add($code)) {
                $d = $m.Groups[2].Value.Trim()
                if ($d) { Add-Insight $Insights 'error' ("${code}: $d") } else { Add-Insight $Insights 'error' $code }
            }
        }
    }
    # OAuth error parameters
    $oa = $Entry['auth']['oauthParams']
    if ($oa.Contains('error')) {
        $m2 = 'OAuth error: ' + $oa['error']
        if ($oa.Contains('error_description') -and $oa['error_description']) { $m2 = $m2 + ' - ' + $oa['error_description'] }
        Add-Insight $Insights 'error' $m2
    }
    # JWT expiry
    foreach ($j in $Jwts) {
        if ($j['expired']) { Add-Insight $Insights 'warning' ("Expired JWT ({0}): expired at {1}" -f $j['where'], $j['expiresAt']) }
    }
    # SAML
    foreach ($s in $Saml) {
        if ($s['statusCode'] -and $s['statusCode'] -notmatch ':Success$') { Add-Insight $Insights 'error' ('SAML status: ' + $s['statusCode']) }
        if ($s['notOnOrAfter']) {
            $d2 = ConvertTo-HarDate $s['notOnOrAfter']
            if ($null -ne $d2 -and $d2 -lt [System.DateTimeOffset]::UtcNow -and $s['kind'] -eq 'response') { Add-Insight $Insights 'warning' ('SAML assertion NotOnOrAfter has passed: ' + $s['notOnOrAfter']) }
        }
    }
    # CORS
    $method = [string]$Entry['method']
    if ($method -eq 'OPTIONS' -and ($status -ge 400 -or $status -eq 0)) { Add-Insight $Insights 'error' 'CORS preflight (OPTIONS) request failed' }
    if ($err -match '(?i)CORS') { Add-Insight $Insights 'error' ('CORS error: ' + $err) }
    $origin = [string](Get-HeaderValue $ReqHeaders 'origin')
    if ($origin -and $status -gt 0 -and $Entry['scheme'] -match '^https?$') {
        $self = $Entry['scheme'] + '://' + $Entry['host']
        $uriObj = $null
        if ([System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$uriObj) -and -not $uriObj.IsDefaultPort) { $self = $self + ':' + $uriObj.Port }
        if (-not [string]::Equals($origin, $self, [System.StringComparison]::OrdinalIgnoreCase) -and $null -eq (Get-HeaderValue $RespHeaders 'access-control-allow-origin')) {
            Add-Insight $Insights 'warning' ("Cross-origin request (Origin: $origin) but the response has no Access-Control-Allow-Origin header")
        }
    }
    # Mixed content
    $page = [string](Get-HeaderValue $ReqHeaders 'referer')
    if (-not $page) { $page = $origin }
    if ($page -match '^https://' -and ($Entry['scheme'] -eq 'http' -or $Entry['scheme'] -eq 'ws')) { Add-Insight $Insights 'warning' ('Mixed content: insecure request from an HTTPS page (' + $page + ')') }
    # Cookies
    foreach ($c in $Entry['respCookies']) {
        if ($c['sameSite'] -ieq 'none' -and -not $c['secure']) { Add-Insight $Insights 'warning' ("Cookie '{0}' uses SameSite=None without Secure (browsers reject it)" -f $c['name']) }
    }
    # Large headers / cookies
    foreach ($pair in @(@('Request', $ReqHeaders), @('Response', $RespHeaders))) {
        $sz = 0
        foreach ($h in $pair[1]) { $sz += ([string]$h['name']).Length + ([string]$h['value']).Length + 4 }
        if ($sz -gt 8192) { Add-Insight $Insights 'warning' ("{0} headers are very large ({1:N1} KB > 8 KB)" -f $pair[0], ($sz / 1024)) }
    }
    $ck = [string](Get-HeaderValue $ReqHeaders 'cookie')
    if ($ck.Length -gt 8192) { Add-Insight $Insights 'warning' ('Cookie header is very large ({0:N1} KB > 8 KB)' -f ($ck.Length / 1024)) }
    # Timing
    $t = $Entry['timings']
    if ($t['wait'] -gt 1000) { Add-Insight $Insights 'warning' ('Slow TTFB: {0:N0} ms waiting for the first byte' -f $t['wait']) }
    if ($t['blocked'] -gt 500) { Add-Insight $Insights 'warning' ('Long blocked/queued time: {0:N0} ms' -f $t['blocked']) }
    # Authentication challenges
    $wa = Get-HeaderValues $RespHeaders 'www-authenticate'
    if ($wa.Count -gt 0) {
        $schemes = New-Object 'System.Collections.Generic.List[string]'
        foreach ($w in $wa) { foreach ($m3 in [regex]::Matches($w, '(?i)\b(Negotiate|NTLM|Bearer|Basic|Digest|Kerberos)\b')) { if (-not $schemes.Contains($m3.Value)) { $schemes.Add($m3.Value) } } }
        $sev2 = 'info'
        if ($status -eq 401) { $sev2 = 'warning' }
        $label = 'WWW-Authenticate challenge'
        if ($schemes.Count -gt 0) { $label = $label + ': ' + ($schemes -join ', ') }
        Add-Insight $Insights $sev2 $label
    }
    if ($Entry['fromCache']) { Add-Insight $Insights 'info' 'Served from browser cache' }
}
#endregion

#region Add-RedirectInsights
function Add-RedirectInsights {
    # Cross-entry check: follows redirectURL hops and flags loops.
    param($Entries)
    $byUrl = @{}
    for ($i = 0; $i -lt $Entries.Count; $i++) {
        $u = ([string]$Entries[$i]['url']).Split('#')[0]
        if (-not $byUrl.ContainsKey($u)) { $byUrl[$u] = New-Object 'System.Collections.Generic.List[int]' }
        $byUrl[$u].Add($i)
    }
    $done = New-Object 'System.Collections.Generic.HashSet[int]'
    for ($i = 0; $i -lt $Entries.Count; $i++) {
        $e = $Entries[$i]
        if (-not $e['redirectURL'] -or $done.Contains($i)) { continue }
        $chain = New-Object 'System.Collections.Generic.List[int]'
        $visited = New-Object 'System.Collections.Generic.HashSet[string]'
        $cur = $i
        $loop = $false
        $loopUrl = ''
        while ($true) {
            $ce = $Entries[$cur]
            $chain.Add($cur)
            [void]$done.Add($cur)
            $cu = ([string]$ce['url']).Split('#')[0]
            if (-not $visited.Add($cu)) { $loop = $true; $loopUrl = $cu; break }
            if (-not $ce['redirectURL']) { break }
            $next = $null
            try {
                $base = New-Object System.Uri($cu)
                $next = (New-Object System.Uri($base, [string]$ce['redirectURL'])).AbsoluteUri.Split('#')[0]
            } catch { break }
            if ($visited.Contains($next)) { $loop = $true; $loopUrl = $next; break }
            if (-not $byUrl.ContainsKey($next)) { break }
            $nj = -1
            foreach ($cand in $byUrl[$next]) { if ($cand -gt $cur) { $nj = $cand; break } }
            if ($nj -lt 0) { break }
            $cur = $nj
        }
        if ($loop) {
            foreach ($ix in $chain) { Add-Insight $Entries[$ix]['insights'] 'error' ('Redirect loop detected: ' + $loopUrl) }
        } elseif ($chain.Count -ge 10) {
            foreach ($ix in $chain) { Add-Insight $Entries[$ix]['insights'] 'warning' ("Long redirect chain ({0} hops)" -f $chain.Count) }
        }
    }
}
#endregion

#region ConvertTo-NormalizedEntry
function ConvertTo-NormalizedEntry {
    param($Entry, [int]$Index)
    $redact = $script:Redact
    $req = Get-Prop $Entry 'request'
    if ($null -eq $req) { throw 'entry has no request object' }
    $resp = Get-Prop $Entry 'response'
    if ($null -eq $resp) { $resp = [ordered]@{} }
    $ins = New-Object 'System.Collections.Generic.List[object]'

    $urlRaw = [string](Get-Prop $req 'url' '')
    if (-not $urlRaw) { throw 'request.url is missing' }
    $method = ([string](Get-Prop $req 'method' 'GET')).ToUpperInvariant()
    $started = ConvertTo-HarDate (Get-Prop $Entry 'startedDateTime')
    if ($null -eq $started) { $started = [System.DateTimeOffset]$script:Epoch; Add-Insight $ins 'warning' 'startedDateTime missing or invalid.' }

    $uri = $null
    [void][System.Uri]::TryCreate($urlRaw, [System.UriKind]::Absolute, [ref]$uri)
    $scheme = ''
    $hostName = ''
    $path = ''
    if ($null -ne $uri) {
        $scheme = $uri.Scheme
        $hostName = $uri.Host
        try { $path = $uri.AbsolutePath } catch { $path = '' }
    }

    # Headers (raw copies are used for analysis; masked copies are emitted)
    $reqHdrRaw = Read-Pairs (Get-Prop $req 'headers')
    $respHdrRaw = Read-Pairs (Get-Prop $resp 'headers')
    $content = Get-Prop $resp 'content'
    $respCt = [string](Get-HeaderValue $respHdrRaw 'content-type')
    $contentMime = [string](Get-Prop $content 'mimeType' '')
    if (-not $respCt) { $respCt = $contentMime }
    $mime = Get-MimeBase $respCt
    if (-not $mime) { $mime = Get-MimeBase $contentMime }

    $declaredType = [string](Get-Prop $Entry '_resourceType' '')
    $resourceType = Get-ResourceType $declaredType $mime $scheme $path
    $isStatic = ($resourceType -in 'image', 'font', 'stylesheet', 'media')

    $status = [int](Get-Num (Get-Prop $resp 'status' 0))
    $statusText = [string](Get-Prop $resp 'statusText' '')
    $httpVersion = [string](Get-Prop $resp 'httpVersion' '')
    if (-not $httpVersion) { $httpVersion = [string](Get-Prop $req 'httpVersion' '') }
    switch -Regex ($httpVersion.ToLowerInvariant()) {
        '^(h2|h2c|http/2(\.0)?)$' { $httpVersion = 'HTTP/2' }
        '^(h3|http/3(\.0)?)$' { $httpVersion = 'HTTP/3' }
        '^http/1\.[01]$' { $httpVersion = $httpVersion.ToUpperInvariant() }
    }

    $err = [string](Get-Prop $Entry '_error' '')
    if (-not $err) { $err = [string](Get-Prop $resp '_error' '') }
    if (-not $err) { $err = [string](Get-Prop $Entry '_failureText' '') }

    # Cookies
    $reqCookiesRaw = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ch in (Get-HeaderValues $reqHdrRaw 'cookie')) {
        foreach ($part in $ch.Split(';')) {
            $eq = $part.IndexOf('=')
            if ($eq -gt 0) { $reqCookiesRaw.Add([ordered]@{ name = $part.Substring(0, $eq).Trim(); value = $part.Substring($eq + 1).Trim() }) }
        }
    }
    if ($reqCookiesRaw.Count -eq 0) { foreach ($c in (Read-Pairs (Get-Prop $req 'cookies'))) { $reqCookiesRaw.Add($c) } }
    $respCookiesRaw = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sc in (Get-HeaderValues $respHdrRaw 'set-cookie')) {
        foreach ($line in ($sc -split "\r?\n")) { if ($line.Trim()) { $respCookiesRaw.Add((Parse-SetCookie $line)) } }
    }
    if ($respCookiesRaw.Count -eq 0) {
        foreach ($c in (Get-List (Get-Prop $resp 'cookies'))) {
            if ($null -eq $c) { continue }
            $respCookiesRaw.Add([ordered]@{
                    name = [string](Get-Prop $c 'name' ''); value = [string](Get-Prop $c 'value' ''); domain = [string](Get-Prop $c 'domain' '')
                    path = [string](Get-Prop $c 'path' ''); expires = [string](Get-Prop $c 'expires' ''); secure = [bool](Get-Prop $c 'secure' $false)
                    httpOnly = [bool](Get-Prop $c 'httpOnly' $false); sameSite = [string](Get-Prop $c 'sameSite' '')
                })
        }
    }

    # Query string
    $queryRaw = $null
    $qi = $urlRaw.IndexOf('?')
    if ($qi -ge 0) { $queryRaw = Get-QueryParameters $urlRaw.Substring($qi) }
    else { $queryRaw = Read-Pairs (Get-Prop $req 'queryString') }

    # Request body
    $pd = Get-Prop $req 'postData'
    $reqCt = [string](Get-HeaderValue $reqHdrRaw 'content-type')
    if (-not $reqCt) { $reqCt = [string](Get-Prop $pd 'mimeType' '') }
    $postText = Get-Prop $pd 'text'
    if ($null -eq $postText -and $null -ne $pd) {
        $pp = Get-List (Get-Prop $pd 'params')
        if ($pp.Count -gt 0) {
            $sbp = New-Object System.Text.StringBuilder
            foreach ($p in $pp) {
                if ($sbp.Length -gt 0) { [void]$sbp.Append('&') }
                [void]$sbp.Append([System.Uri]::EscapeDataString([string](Get-Prop $p 'name' ''))).Append('=').Append([System.Uri]::EscapeDataString([string](Get-Prop $p 'value' '')))
            }
            $postText = $sbp.ToString()
            if (-not $reqCt) { $reqCt = 'application/x-www-form-urlencoded' }
        }
    }
    $reqRes = Expand-Body -Text $postText -IsBase64 $false -ContentType $reqCt -ContentEncoding ([string](Get-HeaderValue $reqHdrRaw 'content-encoding')) `
        -DeclaredSize (Get-Num (Get-Prop $req 'bodySize' 0)) -CompressedSize 0 -Insights $ins -Side 'Request' -Redact $redact
    $reqBody = $reqRes.Model

    # Response body
    $encoding = [string](Get-Prop $content 'encoding' '')
    $respRes = Expand-Body -Text (Get-Prop $content 'text') -IsBase64 ($encoding -eq 'base64') -ContentType $respCt `
        -ContentEncoding ([string](Get-HeaderValue $respHdrRaw 'content-encoding')) -DeclaredSize (Get-Num (Get-Prop $content 'size' 0)) `
        -CompressedSize (Get-Num (Get-Prop $resp 'bodySize' 0)) -Insights $ins -Side 'Response' -Redact $redact
    $respBody = $respRes.Model

    # Redirect
    $redirect = [string](Get-Prop $resp 'redirectURL' '')
    if (-not $redirect -and $status -ge 300 -and $status -lt 400) { $redirect = [string](Get-HeaderValue $respHdrRaw 'location') }

    # Auth: JWT / SAML / OAuth parameters (analysed on unredacted data)
    $jwts = New-Object 'System.Collections.Generic.List[object]'
    $seenJ = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($h in $reqHdrRaw) { Add-JwtsFromText $h['value'] ('Request header: ' + $h['name']) $jwts $seenJ }
    foreach ($c in $reqCookiesRaw) { Add-JwtsFromText $c['value'] ('Request cookie: ' + $c['name']) $jwts $seenJ }
    foreach ($q in $queryRaw) { Add-JwtsFromText $q['value'] ('Query parameter: ' + $q['name']) $jwts $seenJ }
    $formRaw = $reqRes.Params
    if ($null -ne $formRaw) { foreach ($q in $formRaw) { Add-JwtsFromText $q['value'] ('Form parameter: ' + $q['name']) $jwts $seenJ } }
    elseif ($reqBody.format -ne 'multipart') { Add-JwtsFromText ([string]$reqRes.Text) 'Request body' $jwts $seenJ }
    foreach ($h in $respHdrRaw) { Add-JwtsFromText $h['value'] ('Response header: ' + $h['name']) $jwts $seenJ }
    Add-JwtsFromText ([string]$respRes.Text) 'Response body' $jwts $seenJ

    $samls = New-Object 'System.Collections.Generic.List[object]'
    $samlSources = New-Object 'System.Collections.Generic.List[object]'
    foreach ($q in $queryRaw) { $samlSources.Add(@{ Name = $q['name']; Value = $q['value']; Where = 'Query parameter' }) }
    if ($null -ne $formRaw) { foreach ($q in $formRaw) { $samlSources.Add(@{ Name = $q['name']; Value = $q['value']; Where = 'Form parameter' }) } }
    if ($respBody.format -eq 'html') { foreach ($x in (Get-HtmlSamlInputs ([string]$respRes.Text))) { $samlSources.Add(@{ Name = $x.Name; Value = $x.Value; Where = 'Response HTML form' }) } }
    foreach ($s in $samlSources) {
        if ($samls.Count -ge 10) { break }
        $kind = ''
        if ($s.Name -ieq 'SAMLRequest') { $kind = 'request' } elseif ($s.Name -ieq 'SAMLResponse') { $kind = 'response' } else { continue }
        $parsed = ConvertFrom-Saml $s.Value $kind ($s.Where + ': ' + $s.Name)
        if ($null -ne $parsed) { $samls.Add($parsed) } else { Add-Insight $ins 'warning' ("SAML decoding of $($s.Name) failed (could not base64-decode/inflate/parse the value).") }
    }

    $oauth = [ordered]@{}
    $addOAuth = {
        param($pairs)
        foreach ($q in $pairs) {
            $nm = [string]$q['name']
            if ($script:OAuthNames.Contains($nm) -and -not $oauth.Contains($nm.ToLowerInvariant())) {
                $oauth[$nm.ToLowerInvariant()] = Protect-Secrets -Mode Param -Name $nm -Value ([string]$q['value'])
            }
        }
    }
    & $addOAuth $queryRaw
    if ($null -ne $formRaw) { & $addOAuth $formRaw }
    if ($redirect) {
        $ri = $redirect.IndexOf('?')
        if ($ri -ge 0) { & $addOAuth (Get-QueryParameters $redirect.Substring($ri)) }
        $fi = $redirect.IndexOf('#')
        if ($fi -ge 0) { & $addOAuth (Get-QueryParameters ('?' + $redirect.Substring($fi + 1))) }
    }
    $fi2 = $urlRaw.IndexOf('#')
    if ($fi2 -ge 0) { & $addOAuth (Get-QueryParameters ('?' + $urlRaw.Substring($fi2 + 1))) }
    if ($respBody.format -eq 'json' -and ([string]$respRes.Text).Length -lt 2097152) {
        try {
            $obj = ConvertFrom-JsonText ([string]$respRes.Text)
            if ($obj -is [System.Collections.IDictionary] -and (([System.Collections.IDictionary]$obj).Contains('error') -or ([System.Collections.IDictionary]$obj).Contains('token_type') -or ([System.Collections.IDictionary]$obj).Contains('access_token'))) {
                foreach ($k in 'error', 'error_description', 'error_codes', 'error_uri', 'suberror', 'token_type', 'expires_in', 'ext_expires_in', 'scope', 'resource', 'trace_id', 'correlation_id') {
                    $val = Get-Prop $obj $k
                    if ($null -eq $val -or $val -is [System.Collections.IDictionary]) { continue }
                    if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = (@($val) -join ',') }
                    if (-not $oauth.Contains($k)) { $oauth[$k] = [string]$val }
                }
            }
        } catch { }
    }

    # WebSocket frames
    $ws = New-Object 'System.Collections.Generic.List[object]'
    foreach ($m in (Get-List (Get-Prop $Entry '_webSocketMessages'))) {
        if ($null -eq $m) { continue }
        try {
            $data = [string](Get-Prop $m 'data' '')
            $tm = Get-Prop $m 'time'
            $tIso = ''
            $tMs = 0
            if ($null -ne $tm) {
                $tn = Get-Num $tm 0
                if ($tn -gt 0) {
                    $tMs = [int64][Math]::Floor($tn * 1000)
                    $tIso = Format-IsoUtc ([System.DateTimeOffset]$script:Epoch.AddMilliseconds($tMs))
                }
            }
            $frame = [ordered]@{ type = [string](Get-Prop $m 'type' ''); time = $tIso; timeMs = $tMs; opcode = [int](Get-Num (Get-Prop $m 'opcode' 0)); data = $data }
            $trim = $data.TrimStart()
            if ($trim.Length -gt 1 -and ($trim[0] -eq '{' -or $trim[0] -eq '[')) { try { $frame['pretty'] = Format-Json $data } catch { } }
            if ($redact) {
                $frame['data'] = Protect-Secrets -Mode Text -Value $data
                if ($frame.Contains('pretty')) { $frame['pretty'] = Protect-Secrets -Mode Text -Value $frame['pretty'] }
            }
            $ws.Add($frame)
        } catch { Add-Insight $ins 'warning' ('WebSocket frame decoding failed: ' + $_.Exception.Message) }
    }

    # Timings
    $tRaw = Get-Prop $Entry 'timings'
    $timings = [ordered]@{}
    $sum = 0.0
    foreach ($k in 'blocked', 'dns', 'connect', 'ssl', 'send', 'wait', 'receive') {
        $v = Get-Num (Get-Prop $tRaw $k 0)
        if ($v -lt 0) { $v = 0 }
        $v = [Math]::Round($v, 3)
        $timings[$k] = $v
        if ($k -ne 'ssl') { $sum += $v }
    }
    $total = Get-Num (Get-Prop $Entry 'time' -1) -1
    if ($total -lt 0) { $total = $sum }
    $timings['total'] = [Math]::Round($total, 3)

    # Assemble (masked output)
    $e = [ordered]@{}
    $e['id'] = $Index + 1
    $e['startedDateTime'] = Format-IsoUtc $started
    $e['startedMs'] = [int64][Math]::Floor(($started.UtcDateTime - $script:Epoch).TotalMilliseconds)
    $e['pageRef'] = [string](Get-Prop $Entry 'pageref' '')
    $e['method'] = $method
    $e['url'] = $(if ($redact) { Protect-Secrets -Mode Url -Value $urlRaw } else { $urlRaw })
    $e['scheme'] = $scheme
    $e['host'] = $hostName
    $e['path'] = $path
    $e['httpVersion'] = $httpVersion
    $e['status'] = $status
    $e['statusText'] = $statusText
    $e['serverIp'] = [string](Get-Prop $Entry 'serverIPAddress' '')
    $conn = [string](Get-Prop $Entry 'connection' '')
    if (-not $conn -and $null -ne $uri) { $conn = [string]$uri.Port }
    $e['connection'] = $conn
    $e['resourceType'] = $resourceType
    $e['mimeType'] = $mime
    $e['isStatic'] = $isStatic
    $fc = Get-Prop $Entry '_fromCache'
    $e['fromCache'] = ($null -ne $fc -and $fc -ne $false -and [string]$fc -ne '')
    if ($redact) {
        $e['reqHeaders'] = Protect-PairList $reqHdrRaw 'Header'
        $e['reqCookies'] = Protect-PairList $reqCookiesRaw 'Param'
        $e['queryParams'] = Protect-PairList $queryRaw 'Param'
        $e['respHeaders'] = Protect-PairList $respHdrRaw 'Header'
        $e['respCookies'] = Protect-PairList $respCookiesRaw 'Param'
        foreach ($c in $e['reqCookies']) { $c['value'] = Get-MaskedValue ([string]$c['value']) }
        foreach ($c in $e['respCookies']) { $c['value'] = Get-MaskedValue ([string]$c['value']) }
    } else {
        $e['reqHeaders'] = $reqHdrRaw
        $e['reqCookies'] = $reqCookiesRaw
        $e['queryParams'] = $queryRaw
        $e['respHeaders'] = $respHdrRaw
        $e['respCookies'] = $respCookiesRaw
    }
    $e['reqBody'] = $reqBody
    $e['respBody'] = $respBody
    $e['timings'] = $timings
    $e['redirectURL'] = $(if ($redact) { Protect-Secrets -Mode Url -Value $redirect } else { $redirect })
    $e['correlation'] = Get-CorrelationIds $reqHdrRaw $respHdrRaw
    $e['auth'] = [ordered]@{ jwt = $jwts; saml = $samls; oauthParams = $oauth }
    $e['wsMessages'] = $ws
    $e['error'] = $err

    # Keep browser-specific fields
    if ($Entry -is [System.Collections.IDictionary]) {
        foreach ($k in $Entry.Keys) {
            $ks = [string]$k
            if ($ks.StartsWith('_') -and $ks -ne '_webSocketMessages' -and $ks -ne '_error' -and $ks -ne '_failureText' -and -not ($redact -and $ks -eq '_initiator')) { $e[$ks] = $Entry[$k] }
        }
    }

    # Insights
    $texts = New-Object 'System.Collections.Generic.List[string]'
    $texts.Add((ConvertFrom-UrlEncoded $urlRaw))
    if ($redirect) { $texts.Add((ConvertFrom-UrlEncoded $redirect)) }
    $rt = [string]$respRes.Text
    if ($rt.Length -gt 400000) { $rt = $rt.Substring(0, 400000) }
    $texts.Add($rt)
    $qt = [string]$reqRes.Text
    if ($qt.Length -gt 100000) { $qt = $qt.Substring(0, 100000) }
    $texts.Add($qt)
    Get-EntryInsights -Entry $e -ReqHeaders $reqHdrRaw -RespHeaders $respHdrRaw -Jwts $jwts -Saml $samls -SearchTexts $texts -Insights $ins
    $e['insights'] = $ins
    return $e
}
#endregion

#region New-HarError
function New-HarError {
    param([string]$Message, [int]$Code)
    $ex = New-Object System.Exception $Message
    $ex.Data['ExitCode'] = $Code
    throw $ex
}
#endregion

#region Read-HarFile
function Read-HarFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { New-HarError "HAR file not found: $Path" 1 }
    try { $bytes = [System.IO.File]::ReadAllBytes($Path) } catch { New-HarError ("Cannot read '$Path': " + $_.Exception.Message) 1 }
    if ($bytes.Length -eq 0) { New-HarError "HAR file is empty: $Path" 1 }
    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $offset = 3 }
    $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes, $offset, $bytes.Length - $offset)
    $bytes = $null
    try { $root = ConvertFrom-JsonText $text } catch { New-HarError ("The file is not valid JSON (corrupted or not a HAR file): " + $_.Exception.Message) 2 }
    $text = $null
    if ($null -eq $root -or $root -is [string] -or $root -is [System.Array]) { New-HarError 'Invalid HAR: the JSON root is not an object.' 1 }
    $log = Get-Prop $root 'log'
    if ($null -eq $log) { New-HarError "Invalid HAR: the 'log' object is missing." 1 }
    $entries = Get-Prop $log 'entries'
    if ($null -eq $entries -or $entries -is [string] -or $entries -isnot [System.Collections.IEnumerable]) { New-HarError "Invalid HAR: 'log.entries' is missing or not an array." 1 }
    $ver = [string](Get-Prop $log 'version' '')
    if ($ver -and $ver -notin '1.1', '1.2') { New-HarError "Unsupported HAR version '$ver' (supported: 1.1, 1.2)." 1 }
    if (-not $ver) { Write-Warning "HAR 'log.version' is missing; assuming 1.2." }
    return ,$log
}
#endregion

#region New-HtmlReport
function New-HtmlReport {
    param($Entries, $Meta, [string]$ReportTitle)
    if ($script:HtmlTemplate.Trim() -eq ('#__HTML_' + 'TEMPLATE__')) { New-HarError 'The embedded HTML template has not been merged into this script (the template placeholder line is still present).' 1 }
    $json = [HarFmt]::ToJson([ordered]@{ meta = $Meta; entries = $Entries })
    $encTitle = [System.Net.WebUtility]::HtmlEncode($ReportTitle)
    # Title first, data last (ordinal replace) so the payload is never touched by another replacement.
    return $script:HtmlTemplate.Replace('__REPORT_TITLE__', $encTitle).Replace('__HAR_DATA__', $json)
}
#endregion

#region Resolve-OutputFile
function Resolve-OutputFile {
    param([string]$InFile)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($InFile)
    $dir = [System.IO.Path]::GetDirectoryName($InFile)
    $cwd = (Get-Location).ProviderPath
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $name = $base + '_Report_' + $stamp + '.html'
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { return (Join-Path $dir $name) }
    $full = $OutputPath
    if (-not [System.IO.Path]::IsPathRooted($full)) { $full = Join-Path $cwd $full }
    $full = [System.IO.Path]::GetFullPath($full)
    $isDir = (Test-Path -LiteralPath $full -PathType Container) -or $OutputPath.EndsWith('\') -or $OutputPath.EndsWith('/')
    if ($isDir) { return (Join-Path $full $name) }
    return $full
}
#endregion

#region Invoke-HarConversion
function Invoke-HarConversion {
    param([string]$InFile)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $leaf = [System.IO.Path]::GetFileName($InFile)
    Write-Verbose "Reading $InFile"
    $log = Read-HarFile $InFile
    Write-Stage $sw 'Stage 1/5: HAR read and validated'

    $rawEntries = Get-List (Get-Prop $log 'entries')
    $total = $rawEntries.Count
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $skipped = 0
    for ($i = 0; $i -lt $total; $i++) {
        if ($total -gt 50 -and ($i % 25) -eq 0) { Write-Progress -Activity "Converting $leaf" -Status ("Entry {0} of {1}" -f ($i + 1), $total) -PercentComplete ([int](100 * $i / $total)) }
        try {
            $e = ConvertTo-NormalizedEntry $rawEntries[$i] $i
            if ($null -ne $e) { $entries.Add($e) }
        } catch {
            $skipped++
            Write-Warning ("Entry #{0} skipped (malformed): {1}" -f ($i + 1), $_.Exception.Message)
        }
        $rawEntries[$i] = $null
    }
    Write-Progress -Activity "Converting $leaf" -Completed
    Write-Stage $sw ("Stage 2-3/5: {0} entries normalized and decoded ({1} skipped/filtered)" -f $entries.Count, ($total - $entries.Count))

    Add-RedirectInsights $entries
    Write-Stage $sw 'Stage 4/5: cross-entry insights (redirect loops)'

    $pages = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in (Get-List (Get-Prop $log 'pages'))) {
        if ($null -eq $p) { continue }
        $pd = ConvertTo-HarDate (Get-Prop $p 'startedDateTime')
        $pages.Add([ordered]@{ id = [string](Get-Prop $p 'id' ''); title = [string](Get-Prop $p 'title' ''); startedDateTime = $(if ($null -ne $pd) { Format-IsoUtc $pd } else { '' }) })
    }
    $minMs = [int64]0
    $maxMs = [int64]0
    foreach ($e in $entries) {
        $s = [int64]$e['startedMs']
        $en = $s + [int64]$e['timings']['total']
        if ($minMs -eq 0 -or $s -lt $minMs) { $minMs = $s }
        if ($en -gt $maxMs) { $maxMs = $en }
    }
    $iso = { param($ms) if ($ms -le 0) { return '' } return (Format-IsoUtc ([System.DateTimeOffset]$script:Epoch.AddMilliseconds($ms))) }
    $creator = Get-Prop $log 'creator'
    $browser = Get-Prop $log 'browser'
    $nv = { param($o) (([string](Get-Prop $o 'name' '')) + ' ' + ([string](Get-Prop $o 'version' ''))).Trim() }
    $reportTitle = $leaf
    $meta = [ordered]@{
        title = $reportTitle
        sourceFile = $leaf
        generatedAt = (Format-IsoUtc ([System.DateTimeOffset]::UtcNow))
        harVersion = [string](Get-Prop $log 'version' '')
        creator = (& $nv $creator)
        browser = (& $nv $browser)
        captureStart = (& $iso $minMs)
        captureEnd = (& $iso $maxMs)
        redacted = $script:Redact
        pages = $pages
    }

    $html = New-HtmlReport -Entries $entries -Meta $meta -ReportTitle $reportTitle
    Write-Stage $sw 'Stage 5/5: HTML generated'
    $out = Resolve-OutputFile $InFile
    $outDir = [System.IO.Path]::GetDirectoryName($out)
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
    [System.IO.File]::WriteAllText($out, $html, (New-Object System.Text.UTF8Encoding($true)))
    Write-Stage $sw "Report written: $out"

    $errCount = 0
    foreach ($e in $entries) { if ($e['status'] -ge 400 -or $e['status'] -eq 0) { $errCount++ } }
    Write-Host ''
    Write-Host "HAR2HTML report created" -ForegroundColor Green
    Write-Host ("  Source  : {0}" -f $InFile)
    Write-Host ("  Entries : {0}{1}" -f $entries.Count, $(if ($skipped -gt 0) { " ($skipped skipped)" } else { '' }))
    Write-Host ("  Errors  : {0} (4xx/5xx/failed)" -f $errCount)
    Write-Host ("  Output  : {0}" -f $out)
    Write-Host ("  Time    : {0:N2} s" -f $sw.Elapsed.TotalSeconds)
    if ($OpenReport) {
        try { Start-Process -FilePath $out } catch { Write-Warning ("Could not open the report automatically: " + $_.Exception.Message) }
    }
}
#endregion

#region Invoke-HarSpecs
function Invoke-HarSpecs {
    param([string]$Spec)
    $file = $null
    try {
        if (-not (Test-Path -LiteralPath $Spec -PathType Leaf)) { New-HarError "HAR file not found: $Spec" 1 }
        $file = (Resolve-Path -LiteralPath $Spec).ProviderPath
    } catch {
        $code = 1
        if ($_.Exception.Data.Contains('ExitCode')) { $code = [int]$_.Exception.Data['ExitCode'] }
        $host.UI.WriteErrorLine('ERROR: ' + $_.Exception.Message)
        if ($code -gt $script:ExitCode) { $script:ExitCode = $code }
        return
    }
    try {
        Invoke-HarConversion -InFile $file
    } catch {
        $code = 2
        if ($_.Exception.Data.Contains('ExitCode')) { $code = [int]$_.Exception.Data['ExitCode'] }
        Write-Progress -Activity 'Converting' -Completed
        Write-Verbose $_.ScriptStackTrace
        $host.UI.WriteErrorLine(("ERROR processing '{0}': {1}" -f $file, $_.Exception.Message))
        if ($code -gt $script:ExitCode) { $script:ExitCode = $code }
    }
}
#endregion

Initialize-NativeHelpers
Initialize-Constants
}

process {
    $script:ProcessRan = $true
    Invoke-HarSpecs $HarPath
}

end {
    # With redirected stdin Windows PowerShell may skip the process block; handle command-line input here.
    if (-not $script:ProcessRan -and $PSBoundParameters.ContainsKey('HarPath')) { Invoke-HarSpecs $HarPath }
    exit $script:ExitCode
}
