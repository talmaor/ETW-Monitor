using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace ClaudeEtwMonitor;

internal static class Program
{
    private const string SessionName = "ClaudeEtwMonitorSession";

    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var opts = CliOptions.Parse(args);

        if (opts.ShowHelp) { PrintHelp(); return 0; }

        // Offline analysis mode needs no elevation and no live session.
        if (opts.AnalyzePath != null)
            return Analyzer.Run(opts.AnalyzePath);

        // Clipboard/paste watcher: no ETW, no elevation — clipboard + a
        // user-mode keyboard hook, both available without Administrator.
        if (opts.Clipboard)
        {
            var clipTargets = ProcessPicker.Select(opts.Preselect);
            if (clipTargets.Count == 0) { Console.WriteLine("No process selected. Exiting."); return 1; }
            return ClipboardWatcher.Run(clipTargets);
        }

        if (!IsAdministrator())
        {
            Console.WriteLine("ETW real-time tracing requires Administrator. Relaunching elevated...");
            return Relaunch(args);
        }

        Console.WriteLine("=== Claude Code ETW Activity Monitor ===\n");

        var targets = ProcessPicker.Select(opts.Preselect);
        if (targets.Count == 0)
        {
            Console.WriteLine("No process selected. Exiting.");
            return 1;
        }

        var tracker = new TargetTracker(targets);
        var names = new ProcNameCache();
        var primary = targets[0];

        // Which user-mode providers are active for this run.
        var activeProviders = ProviderCatalog.All
            .Where(p => opts.Groups.Contains(p.Group))
            .ToArray();
        var byGuid = activeProviders.ToDictionary(p => p.Guid);

        PrintBanner(tracker, targets, opts, activeProviders);

        var logPath = Path.Combine(Environment.CurrentDirectory,
            $"etw-{tracker.NameOf(primary.Id)}-{primary.Id}" +
            (targets.Count > 1 ? $"+{targets.Count - 1}" : "") +
            $"-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");
        using var logger = new EventLogger(logPath);
        Console.WriteLine($"Logging to: {logPath}\nPress Ctrl+C to stop.\n");

        // A crashed previous run can leave the kernel session orphaned; clear it.
        try
        {
            if (TraceEventSession.GetActiveSessionNames().Contains(SessionName))
            {
                new TraceEventSession(SessionName).Stop();
                Console.WriteLine("(cleaned up an orphaned session from a previous run)");
            }
        }
        catch { /* best effort */ }

        using var session = new TraceEventSession(SessionName)
        {
            StopOnDispose = true,
            BufferSizeMB = 256,
        };

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\nStopping session...");
            session.Stop();
        };

        EnableKernelProviders(session, opts);
        EnableUserProviders(session, activeProviders);

        WireKernelEvents(session, tracker, logger, opts);
        WireUserProviders(session, tracker, names, logger, byGuid);

        // Blocks on the processing thread until session.Stop() is called.
        session.Source.Process();

        Console.WriteLine($"\nDone. Captured {logger.Count} events.\nLog: {logPath}");
        return 0;
    }

    // ---------------------------------------------------------------- providers

    private static void EnableKernelProviders(TraceEventSession session, CliOptions opts)
    {
        var keywords =
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.NetworkTCPIP |
            KernelTraceEventParser.Keywords.ImageLoad;

        if (opts.Files)    keywords |= KernelTraceEventParser.Keywords.FileIOInit;
        if (opts.Registry) keywords |= KernelTraceEventParser.Keywords.Registry;

        session.EnableKernelProvider(keywords);
    }

    private static void EnableUserProviders(TraceEventSession session, EtwProvider[] providers)
    {
        foreach (var p in providers)
        {
            try
            {
                session.EnableProvider(p.Guid, TraceEventLevel.Verbose, ulong.MaxValue);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"  ! could not enable {p.Name}: {ex.Message}");
                Console.ResetColor();
            }
        }
    }

    // ------------------------------------------------------------- kernel events

    private static void WireKernelEvents(TraceEventSession session, TargetTracker tracker,
                                         EventLogger log, CliOptions opts)
    {
        var k = session.Source.Kernel;

        k.ProcessStart += d =>
        {
            if (tracker.OnProcessStart(d.ProcessID, d.ParentID, d.ProcessName))
                log.Write("PROC", d.ProcessID, d.ProcessName,
                    $"start  parent={d.ParentID}  cmd: {d.CommandLine}",
                    new Dictionary<string, object?>
                    {
                        ["parentPid"] = d.ParentID,
                        ["commandLine"] = d.CommandLine,
                        ["imageFileName"] = d.ImageFileName,
                    }, raw: d);
        };
        k.ProcessStop += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
            {
                log.Write("PROC", d.ProcessID, d.ProcessName, $"exit   code={d.ExitStatus}", raw: d);
                tracker.OnProcessStop(d.ProcessID);
            }
        };

        k.TcpIpConnect += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
                log.Write("NET", d.ProcessID, tracker.NameOf(d.ProcessID),
                    $"TCP connect {d.saddr}:{d.sport} -> {d.daddr}:{d.dport}",
                    Net(d.daddr.ToString(), d.dport, "tcp-connect"), raw: d);
        };
        k.TcpIpSend += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
                log.Write("NET", d.ProcessID, tracker.NameOf(d.ProcessID),
                    $"TCP send {d.size}B -> {d.daddr}:{d.dport}",
                    Net(d.daddr.ToString(), d.dport, "tcp-send", d.size), raw: d);
        };
        k.TcpIpRecv += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
                log.Write("NET", d.ProcessID, tracker.NameOf(d.ProcessID),
                    $"TCP recv {d.size}B <- {d.daddr}:{d.dport}",
                    Net(d.daddr.ToString(), d.dport, "tcp-recv", d.size), raw: d);
        };
        k.UdpIpSend += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
                log.Write("NET", d.ProcessID, tracker.NameOf(d.ProcessID),
                    $"UDP send {d.size}B -> {d.daddr}:{d.dport}",
                    Net(d.daddr.ToString(), d.dport, "udp-send", d.size), raw: d);
        };

        k.ImageLoad += d =>
        {
            if (tracker.IsTracked(d.ProcessID))
                log.Write("IMG", d.ProcessID, tracker.NameOf(d.ProcessID),
                    $"load {d.FileName}",
                    new Dictionary<string, object?> { ["image"] = d.FileName }, raw: d);
        };

        if (opts.Files)
        {
            k.FileIOCreate += d =>
            {
                if (tracker.IsTracked(d.ProcessID))
                    log.Write("FILE", d.ProcessID, tracker.NameOf(d.ProcessID),
                        $"open {d.FileName}",
                        new Dictionary<string, object?> { ["path"] = d.FileName }, raw: d);
            };
            k.FileIOWrite += d =>
            {
                if (tracker.IsTracked(d.ProcessID))
                    log.Write("FILE", d.ProcessID, tracker.NameOf(d.ProcessID),
                        $"write {d.IoSize}B {d.FileName}",
                        new Dictionary<string, object?> { ["path"] = d.FileName, ["bytes"] = d.IoSize }, raw: d);
            };
        }

        if (opts.Registry)
        {
            k.RegistryOpen += d =>
            {
                if (tracker.IsTracked(d.ProcessID))
                    log.Write("REG", d.ProcessID, tracker.NameOf(d.ProcessID),
                        $"open {d.KeyName}\\{d.ValueName}", raw: d);
            };
            k.RegistrySetValue += d =>
            {
                if (tracker.IsTracked(d.ProcessID))
                    log.Write("REG", d.ProcessID, tracker.NameOf(d.ProcessID),
                        $"set  {d.KeyName}\\{d.ValueName}", raw: d);
            };
        }
    }

    // --------------------------------------------------------- user-mode events

    private static void WireUserProviders(TraceEventSession session, TargetTracker tracker,
        ProcNameCache names, EventLogger log, Dictionary<Guid, EtwProvider> byGuid)
    {
        // Manifest providers decode through the dynamic parser.
        session.Source.Dynamic.All += d =>
        {
            if (!byGuid.TryGetValue(d.ProviderGuid, out var prov) || !prov.Manifest) return;
            EmitUserEvent(d, prov, tracker, names, log);
        };

        // Legacy WPP providers don't decode via the dynamic parser; pick them up
        // raw from the full stream (gated to just the enabled legacy GUIDs, so
        // this never double-handles the manifest or kernel events above).
        var legacyGuids = byGuid.Values.Where(p => !p.Manifest).Select(p => p.Guid).ToHashSet();
        if (legacyGuids.Count > 0)
        {
            session.Source.AllEvents += d =>
            {
                if (!legacyGuids.Contains(d.ProviderGuid)) return;
                EmitUserEvent(d, byGuid[d.ProviderGuid], tracker, names, log);
            };
        }
    }

    private static void EmitUserEvent(TraceEvent d, EtwProvider prov, TargetTracker tracker,
        ProcNameCache names, EventLogger log)
    {
        bool tracked = tracker.IsTracked(d.ProcessID);

        // In-process providers are reliably attributable: drop other processes.
        // System-wide providers (lsass/RPCSS) fire under a broker PID for the
        // whole machine, so we keep them all and flag attribution as "broker".
        if (prov.Scope == Scope.InProcess && !tracked) return;

        var decoded = EventDecode.Decode(d);
        var shortName = prov.Name.Replace("Microsoft-Windows-", "");
        var actor = tracked ? tracker.NameOf(d.ProcessID) : names.Get(d.ProcessID);

        var fields = new Dictionary<string, object?>
        {
            ["scope"] = prov.Scope.ToString(),
            ["attributedToTarget"] = tracked,
        };

        var summary = $"{shortName} :: {d.EventName}" + (decoded.Length > 0 ? $"  {decoded}" : "");
        if (!tracked) summary += "  [broker — system-wide, not target PID]";

        log.Write(prov.Category, d.ProcessID, actor, summary, fields, raw: d);
    }

    private static Dictionary<string, object?> Net(string dst, int port, string kind, int size = 0) => new()
    {
        ["remote"] = dst,
        ["port"] = port,
        ["kind"] = kind,
        ["bytes"] = size,
    };

    // ------------------------------------------------------------------- output

    private static void PrintBanner(TargetTracker tracker, List<Process> targets, CliOptions opts,
        EtwProvider[] active)
    {
        Console.WriteLine($"\nMonitoring {targets.Count} root process(es) and their descendants:");
        foreach (var t in targets)
            Console.WriteLine($"   • {tracker.NameOf(t.Id)} (PID {t.Id})");

        var kernelCats = "PROC NET DNS IMG" + (opts.Files ? " FILE" : "") + (opts.Registry ? " REG" : "");
        Console.WriteLine($"Kernel categories : {kernelCats}");

        if (active.Length > 0)
        {
            Console.WriteLine("User providers    :");
            foreach (var g in active.GroupBy(p => p.Group))
            {
                var scope = g.Any(p => p.Scope == Scope.SystemWide) ? "system-wide" : "in-process";
                Console.WriteLine($"   [{g.Key}] ({scope}): {string.Join(", ", g.Select(p => p.Name.Replace("Microsoft-Windows-", "")))}");
            }
        }

        if (active.Any(p => p.Scope == Scope.SystemWide))
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(
                "\n  NOTE: auth/RPC-broker providers (NTLM, Kerberos, Schannel, WDigest, RPCSS…)\n" +
                "  execute inside lsass.exe / service hosts, so their events are captured\n" +
                "  SYSTEM-WIDE and tagged [broker]; they cannot be attributed to the target\n" +
                "  PID. Correlate them with the target's NET/DNS activity by timestamp.");
            Console.ResetColor();
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine(@"Claude Code ETW Activity Monitor

Usage: ClaudeEtwMonitor [selection] [groups]

Selection (multi-target — Claude Code runs several node.exe):
  --pid <a,b,c>     attach to these process ids (comma-separated)
  --name <text>     attach to ALL processes whose name contains <text>
  (omit both for an interactive multi-select picker)

Offline analysis (no admin needed):
  --analyze <file.jsonl>   build a holistic report from a captured log

Clipboard / paste watcher (no admin needed):
  --clipboard [--name/--pid]  log clipboard text pasted into the target process
                              (and copies made while it is focused). Attributes
                              pastes to the target via the process tree.

Kernel categories (always on: PROC NET DNS IMG):
  --files           capture file I/O      (noisy)
  --registry        capture registry I/O  (noisy)

User-mode provider groups:
  --auth            NTLM, Kerberos, Schannel, Netlogon   (system-wide / lsass)
  --auth-legacy     classic 'Security: *' SSPI WPP providers + LsaSrv
  --ldap            LDAP client            (in-process)
  --rpc             RPC + RPCSS
  --smb             SMB client             (in-process)
  --winsock         Winsock name resolution / sockets / AFD (in-process)
  --http            WinINet / WinHttp      (node uses BoringSSL, so won't fire)
  --all             enable every group above

Examples:
  ClaudeEtwMonitor --name node --auth --rpc --ldap
  ClaudeEtwMonitor --pid 21344 --all --files");
    }

    // ---------------------------------------------------------------- elevation

    private static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int Relaunch(string[] args)
    {
        var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = string.Join(' ', args),
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory,
        };
        try { Process.Start(psi); return 0; }
        catch (Exception ex)
        {
            Console.WriteLine($"Elevation cancelled or failed: {ex.Message}");
            return 1;
        }
    }
}

internal sealed class CliOptions
{
    public string? Preselect { get; private set; }
    public string? AnalyzePath { get; private set; }
    public bool Files { get; private set; }
    public bool Registry { get; private set; }
    public bool Clipboard { get; private set; }
    public bool ShowHelp { get; private set; }
    public HashSet<string> Groups { get; } = new(ProviderCatalog.DefaultGroups);

    private static readonly string[] AllGroups =
        { "auth", "auth-legacy", "ldap", "rpc", "smb", "winsock", "http", "dns" };

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--pid":
                case "--name":
                    if (i + 1 < args.Length) o.Preselect = args[++i];
                    break;
                case "--analyze":
                    if (i + 1 < args.Length) o.AnalyzePath = args[++i];
                    break;
                case "--files": o.Files = true; break;
                case "--registry": o.Registry = true; break;
                case "--clipboard": case "--paste": o.Clipboard = true; break;
                case "--all": foreach (var g in AllGroups) o.Groups.Add(g); break;
                case "-h": case "--help": case "/?": o.ShowHelp = true; break;
                default:
                    var name = args[i].TrimStart('-').ToLowerInvariant();
                    if (AllGroups.Contains(name)) o.Groups.Add(name);
                    break;
            }
        }
        return o;
    }
}
