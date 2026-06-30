# Claude Code ETW Activity Monitor

A console tool that attaches an **Event Tracing for Windows (ETW)** real-time
session to a chosen process (and its child processes) and reports its activity:
process launches, network connections, DNS lookups, TLS handshakes, DLL loads,
and optionally file & registry I/O.

Built for observing a locally-running Claude Code process under different
permissions/APIs — an introspection/observability experiment on your own machine.

## How it works

1. On launch it lists running processes, highlighting likely Claude Code
   processes (`node.exe`, `claude*`).
2. You pick one by **PID** or **name**.
3. It opens an ETW session, enables the relevant providers, and filters every
   event down to the selected process **plus any children it spawns** (Claude
   Code launches shells, `git`, etc., so the whole tree is followed live).
4. Events stream to the console (color-coded) and to a `etw-<name>-<pid>-<time>.jsonl`
   log file in the working directory.

Press **Ctrl+C** to stop cleanly.

## Captured providers

**Kernel (always on, filtered to the target tree):**

| Category | Provider | What you see |
|----------|----------|--------------|
| `PROC`   | Kernel `Process`        | child process start/stop **with full command line** |
| `NET`    | Kernel `NetworkTCPIP`   | TCP connect/send/recv + UDP, remote IP:port, byte counts |
| `IMG`    | Kernel `ImageLoad`      | DLLs loaded into the process |
| `FILE`   | Kernel `FileIOInit` *(`--files`)* | file opens/writes |
| `REG`    | Kernel `Registry` *(`--registry`)* | registry opens/sets |

**User-mode providers (opt-in by group). GUIDs verified on this machine via `logman query providers`:**

| Group | Provider(s) | Scope | Notes |
|-------|-------------|-------|-------|
| `dns` *(default)* | Microsoft-Windows-DNS-Client | in-process | name resolutions + answers |
| `auth` | NTLM, Security-Kerberos, Schannel-Events, Security-Netlogon | **lsass (system-wide)** | modern manifest providers; decode cleanly |
| `auth-legacy` | `Security: NTLM/Kerberos/SChannel/WDigest/TSPkg`, NTLM Security Protocol, LSA, LsaSrv | **lsass (system-wide)** | classic WPP providers; raw/undecoded without TMF files |
| `ldap` | Microsoft-Windows-LDAP-Client | in-process ✓ | filterable to target |
| `rpc`  | Microsoft-Windows-RPC, RPC-Events, RPCSS | mixed | client stub in-proc; RPCSS is broker |
| `smb`  | Microsoft-Windows-SMBClient | in-process ✓ | filterable to target |
| `winsock` | Winsock NameResolution / AFD / Sockets | in-process ✓ | socket-level detail |
| `http` | WinINet, WinHttp | in-process | node won't fire these (BoringSSL); useful for child tools |

> **Why two NTLM/Kerberos/Schannel rows?** The `Security: *` set you may have seen
> elsewhere are the **legacy WPP** trace providers — they emit but typically need
> `.TMF` symbol files to decode into readable text. The `Microsoft-Windows-*`
> rows are the **modern manifest-based** equivalents that decode out of the box,
> so prefer `--auth` over `--auth-legacy` unless you have the TMFs.

### ⚠️ Auth events are system-wide, not per-process

NTLM / Kerberos / Schannel / WDigest / Negotiate all run inside **lsass.exe**, and
RPCSS inside its service host — SSPI brokers them on behalf of *every* process.
Their ETW events therefore carry the **broker's PID, not node's**, so they cannot
be PID-filtered to the target. This tool captures them **system-wide** and tags
each line `[broker — system-wide, not target PID]`. Correlate them with the
target's `NET`/`DNS` lines **by timestamp** to infer which auth belongs to it.
In-process groups (`ldap`, `smb`, `winsock`, client-side `rpc`) *are* filtered to
the target.

## Usage

```powershell
# From this folder. The app self-elevates via UAC (ETW needs Administrator).
.\run.ps1                                   # interactive picker, DNS only
.\run.ps1 --name node --auth --rpc --ldap   # auth + rpc + ldap on a node process
.\run.ps1 --pid 1234 --all                  # every user provider group
.\run.ps1 --pid 1234 --all --files --registry   # everything incl. local I/O
.\run.ps1 --help                            # full flag list
```

Provider groups: `--auth --auth-legacy --ldap --rpc --smb --winsock --http --all`
(`dns` is always on). `--files` / `--registry` add the noisy kernel categories.

### Monitoring multiple PIDs (Claude Code runs several)

Claude Code spawns several `node.exe` processes. You can capture all of them:

```powershell
.\run.ps1 --name node              # selects EVERY process named *node*
.\run.ps1 --pid 1000,1200,1450     # exactly these PIDs
```

In the interactive picker, type a **name** to grab all matches, or a **comma list
of PIDs**. All selected roots and their descendants are tracked together.

### Capture now, analyze later

Each event is written to the `.jsonl` log with its **complete payload** — every
ETW field plus header metadata (`_provider`, `_event`, `_opcode`, `_tid`,
`_activityId`, `_message`, …) under a `raw` object. Nothing is dropped; the
console line is just a summary.

Then run the analyzer offline (no admin) to get a holistic report:

```powershell
.\run.ps1 --analyze etw-node-1000-20260628-100000.jsonl
```

It produces (and saves a `.analysis.md`) a **security-oriented** report:
- a **security findings** triage table (severity / PID / process / finding) that
  leads the report — LOLBin spawns, browser/URL launches, outbound to public IPs
  with no preceding DNS (direct-IP), connections on sensitive ports (RDP/SMB/LDAP/
  WinRM/…), modules loaded from non-system paths, sensitive file/registry access,
  and NTLM usage
- event volume by category
- the **process tree** with command lines (LOLBins flagged ⚠️)
- a **per-process (per-PID) breakdown**: each PID's endpoints (with resolved
  hostname + bytes), DNS queries, and non-system module loads
- **Web destinations** — explicit URLs (from command lines / HTTP fields) and
  hosts contacted (DNS + TLS SNI), all rendered as **clickable markdown links**
- **DNS resolutions**, used to map IPs → hostnames
- a **network endpoints** table (IP:port → hostname, connections, bytes, PIDs,
  with a note column flagging sensitive ports / direct-IP / internal)
- **auth/SSPI** activity grouped by provider/target/user
- LDAP / RPC / SMB / HTTP event breakdowns

> The DNS map is built from `raw.QueryName` / `raw.QueryResults`, so endpoints and
> hosts are correlated to names wherever the OS resolver was used.

## Can ETW show what URL the user clicked?

Short answer: **no "click" events, and URLs only for apps that use the Windows
HTTP stack** — which Claude Code does not.

- **Clicks are UI, not ETW.** ETW is system/protocol telemetry; there is no
  provider that emits "user clicked link X in PID Y". The closest is raw Win32k
  input (mouse-down coordinates, focus changes) — no semantic URL.
- **URLs via `--http`:** the WinINet / WinHttp providers *do* emit the full
  request URL (scheme + host + path) — but only for processes that use those
  stacks: many .NET/Win32 apps, legacy IE/Edge, `Invoke-WebRequest`, installers,
  etc. For those, enable `--http` and you'll see `URL=…` on `HTTP` lines.
- **Claude Code (node.exe) and Chromium browsers use their own net stacks**
  (BoringSSL / Chromium net), bypassing WinINet/WinHttp, so ETW yields only
  **hostnames** (`--dns`) and **IP:port** (kernel NET) — never full URLs or paths.

To get full URLs/paths or actual click semantics for such an app you need a
different technique: an **MITM proxy** (full URLs + bodies via a trusted CA) or
**UI Automation / input hooking** (clicks) — neither is ETW.

## Clipboard / paste watcher (`--clipboard`)

Clipboard **content never appears in ETW** — the bytes live in shared memory and
the paste reaches a console app over a stdin pipe, so neither the kernel NET/FILE
providers nor any user provider can see it. The `--clipboard` mode is therefore a
**separate, non-ETW tool** (it needs no Administrator): it reads the Win32
clipboard directly and catches paste gestures with a low-level keyboard hook.

```powershell
.\run.ps1 --clipboard --name claude
```

It logs (to `clip-<name>-<pid>-<ts>.jsonl` + console):
- **Pastes into the target** — Ctrl+V / Ctrl+Shift+V / Shift+Insert (keyboard
  hook) and **right-click paste** in console hosts (mouse hook; gated to terminal
  foregrounds so a right-click context-menu in a GUI app isn't mistaken for a
  paste). Captures the clipboard text, length, formats, and any pasted file paths
  (CF_HDROP).
- **Copies made while the target is focused** (data leaving the session), detected
  via the clipboard sequence number.
- **Sensitive-content tagging (DLP-lite).** Each captured text is scanned for
  likely secrets / PII / PHI and tagged in a `sensitive` field; flagged events are
  printed in red with a `⚠`. Patterns: AWS / GitHub / Slack / Google keys, JWTs,
  PEM private keys, `password=`/`api_key=`-style assignments, SSNs, emails, IPs,
  Luhn-valid credit-card numbers, and medical keywords (`patient`, `MRN`,
  `diagnosis`, `DOB`, …). Best-effort surfacing — "you just pasted something
  sensitive into an AI tool" — not an authoritative classifier.
- **Echo suppression.** Chromium/Electron apps (e.g. the Claude desktop app)
  re-write the clipboard with an HTML-normalized copy after a paste, which would
  otherwise re-surface as a duplicate `copy/out`. A `copy` whose text was already
  logged within the last 10 s is dropped. Pastes are deliberate actions and are
  never deduped, even when repeated.

**PID scoping is heuristic, and the tool is honest about it.** Claude is node.exe
with *no window*, so a paste's foreground window is always the hosting terminal.
Attribution walks the **process tree** (is the focused terminal an ancestor/
descendant of the target node PID?) and tags every record with a `confidence`:

| Confidence | Meaning |
|------------|---------|
| `High`     | foreground is the target, or directly ancestor/descendant of it |
| `Medium`   | foreground and target share a terminal ancestor |
| `Low`      | a console host is focused but no tree link proven |
| `None`     | unrelated foreground — **content is not read or logged** |

With **Windows Terminal** (where the shell's parent *is* `WindowsTerminal.exe`)
this is reliable. With classic **conhost** it may only reach `Low`. **Multi-tab
terminals cannot be disambiguated** — we can't know which tab had focus, so a
paste into any tab of a focused terminal hosting the target will be attributed to
it. Pastes into clearly unrelated apps (a browser, Notepad) are skipped entirely,
keeping the capture scoped.

> ⚠️ This mode records clipboard **text content** to disk. Run it only to monitor
> your own machine / sessions.

Or directly:

```powershell
dotnet build -c Release
.\bin\Release\net9.0-windows\ClaudeEtwMonitor.exe --name node
```

## Important limitation — encrypted API traffic

Claude Code runs as **node.exe**, which uses its own TLS stack (BoringSSL), **not**
Windows Schannel / WinHTTP / WinINet. Consequences:

- ✅ You **will** see the TCP connections and DNS lookups to the Anthropic API
  (remote IP, port 443, hostname `api.anthropic.com`), and byte volumes.
- ❌ You will **not** see decrypted HTTP request/response bodies, API keys, or
  Schannel TLS events for those calls — that traffic is encrypted end-to-end by
  the app itself, below ETW's visibility for OS crypto.
- `AUTH`/Schannel events appear only for components that use the Windows crypto
  stack (some native modules, OS auth), not for node's own HTTPS.

To inspect the actual API payloads you'd need an app-level MITM proxy with a
trusted CA and `NODE_EXTRA_CA_CERTS` / proxy env vars pointed at it — a different
technique from ETW.

## Requirements

- Windows 10/11, **Administrator** (auto-elevation prompt on launch)
- .NET 9 SDK (uses `Microsoft.Diagnostics.Tracing.TraceEvent`)

## Output schema (JSONL)

Each line:

```json
{"ts":"14:03:21.882","category":"NET","pid":21344,"process":"node",
 "summary":"TCP connect 10.0.0.5:51322 -> 160.79.104.10:443",
 "remote":"160.79.104.10","port":443,"kind":"tcp-connect","bytes":0}
```
