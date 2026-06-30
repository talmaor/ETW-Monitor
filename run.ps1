# Builds (if needed) and launches the Claude Code ETW monitor.
# The app self-elevates via UAC because ETW real-time sessions need Administrator.
#
#   .\run.ps1                 # interactive process picker
#   .\run.ps1 --name node     # auto-select first matching process
#   .\run.ps1 --pid 1234      # auto-select by PID
#   .\run.ps1 --pid 1234 --files --registry   # also capture file & registry I/O
#   .\run.ps1 --analyze cap.jsonl             # offline report (no admin)
#   .\run.ps1 --clipboard --name claude       # clipboard/paste watcher (no admin)

param([Parameter(ValueFromRemainingArguments = $true)] $Args)

$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'ClaudeEtwMonitor.csproj'

dotnet build $proj -c Release -v quiet | Out-Null
$exe = Join-Path $PSScriptRoot 'bin\Release\net9.0-windows\ClaudeEtwMonitor.exe'

& $exe @Args
