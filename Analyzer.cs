using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeEtwMonitor;

/// <summary>
/// Post-processes a captured .jsonl log into a security-oriented report:
/// a triage summary of notable findings, a process tree, a per-PID breakdown
/// (endpoints / DNS / web destinations / loaded modules), clickable web
/// destinations, DNS resolutions, network endpoints joined with DNS, and auth
/// activity. Runs without Administrator — it only reads a file.
///
///   ClaudeEtwMonitor --analyze etw-node-1234-....jsonl
/// </summary>
internal static class Analyzer
{
    public static int Run(string path)
    {
        if (!File.Exists(path))
        {
            Console.WriteLine($"File not found: {path}");
            return 1;
        }

        var events = new List<Dictionary<string, JsonElement>>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var d = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
                if (d != null) events.Add(d);
            }
            catch { /* skip malformed line */ }
        }

        if (events.Count == 0)
        {
            Console.WriteLine("No events found in log.");
            return 1;
        }

        var sb = new StringBuilder();
        void W(string s = "") { sb.AppendLine(s); }

        // ---- DNS: build ip -> host map once; every later section reuses it ----
        var ipToHost = BuildDnsMap(events);

        // ---- collect security findings up front so the summary leads with them ----
        var findings = CollectFindings(events, ipToHost);

        W("# ETW Capture Analysis");
        W();
        W($"- Source: `{Path.GetFileName(path)}`");
        W($"- Events: **{events.Count}**");
        var first = Str(events[0], "ts");
        var last = Str(events[^1], "ts");
        W($"- Window: {first} → {last}");
        W($"- Findings: **{findings.Count}** "
          + $"({findings.Count(f => f.Sev == Sev.High)} high, "
          + $"{findings.Count(f => f.Sev == Sev.Med)} medium, "
          + $"{findings.Count(f => f.Sev == Sev.Info)} info)");
        W();

        // ---- security triage (leads the report) ----
        W("## Security findings");
        W();
        if (findings.Count == 0) W("_no notable indicators_");
        else
        {
            W("| Sev | PID | Process | Finding |");
            W("|-----|-----|---------|---------|");
            foreach (var f in findings.OrderByDescending(f => f.Sev).ThenBy(f => f.Pid))
                W($"| {SevTag(f.Sev)} | {(f.Pid > 0 ? f.Pid.ToString() : "—")} | {f.Process} | {f.Message} |");
        }
        W();

        // ---- category breakdown ----
        W("## Event volume by category");
        W();
        foreach (var g in events.GroupBy(e => Str(e, "category")).OrderByDescending(g => g.Count()))
            W($"- `{g.Key}` × {g.Count()}");
        W();

        // ---- process tree ----
        W("## Process tree");
        W();
        BuildProcessTree(events, W);

        // ---- per-PID breakdown ----
        W("## Per-process activity");
        W();
        BuildPerPid(events, ipToHost, W);

        // ---- web destinations (clickable) ----
        W("## Web destinations");
        W();
        BuildWebDestinations(events, ipToHost, W);

        // ---- DNS ----
        W("## DNS resolutions");
        W();
        var dns = events.Where(e => Str(e, "category") == "DNS").ToList();
        if (dns.Count == 0) W("_none_");
        else
        {
            foreach (var g in dns.GroupBy(e => RawStr(e, "QueryName")).OrderBy(g => g.Key))
            {
                if (string.IsNullOrEmpty(g.Key)) continue;
                var results = g.Select(e => RawStr(e, "QueryResults"))
                               .FirstOrDefault(r => !string.IsNullOrEmpty(r)) ?? "";
                var ips = ExtractIps(results).Distinct().ToList();
                var procs = string.Join(",", g.Select(e => Str(e, "process")).Distinct());
                W($"- **{LinkHost(g.Key)}** ×{g.Count()} _(pid {procs})_"
                  + (ips.Count > 0 ? $" → {string.Join(", ", ips)}" : ""));
            }
        }
        W();

        // ---- network endpoints ----
        W("## Network endpoints (TCP/UDP)");
        W();
        var net = events.Where(e => Str(e, "category") == "NET").ToList();
        if (net.Count == 0 || net.All(e => string.IsNullOrEmpty(Str(e, "remote")))) W("_none_");
        else
        {
            var byEndpoint = net
                .Select(e => new
                {
                    Remote = Str(e, "remote"),
                    Port = Str(e, "port"),
                    Kind = Str(e, "kind"),
                    Bytes = Num(e, "bytes"),
                    Proc = Str(e, "pid"),
                })
                .Where(x => !string.IsNullOrEmpty(x.Remote))
                .GroupBy(x => $"{x.Remote}:{x.Port}")
                .OrderByDescending(g => g.Where(x => IsSend(x.Kind)).Sum(x => x.Bytes)) // most data shared out first
                .ToList();

            W("_Bytes are encrypted transport payload (TLS/QUIC); volume is accurate, content is not visible. "
              + "`Sent` is reliable. `Recv` is a **lower bound**: TCP receives are undercounted by the kernel "
              + "provider, and UDP/QUIC receives (HTTP/3 on :443) are not captured at all — so a `0 B` Recv "
              + "next to large Sent usually means QUIC, not a one-way transfer._");
            W();
            W("| Endpoint | Host (via DNS) | Conn | Sent → (out) | Recv ← (in) | PIDs | Note |");
            W("|----------|----------------|------|-------------|------------|------|------|");
            foreach (var g in byEndpoint)
            {
                var ip = g.First().Remote;
                var port = g.First().Port;
                var host = ipToHost.TryGetValue(ip, out var h) ? LinkHost(h) : "";
                var conns = g.Count(x => x.Kind == "tcp-connect");
                var sent = g.Where(x => IsSend(x.Kind)).Sum(x => x.Bytes);
                var recv = g.Where(x => IsRecv(x.Kind)).Sum(x => x.Bytes);
                var pids = string.Join(",", g.Select(x => x.Proc).Distinct());
                var note = EndpointNote(ip, port, host.Length > 0);
                W($"| `{g.Key}` | {host} | {conns} | {Human(sent)} | {Human(recv)} | {pids} | {note} |");
            }
        }
        W();

        // ---- auth ----
        W("## Authentication / SSPI activity (system-wide — correlate by time)");
        W();
        var auth = events.Where(e => Str(e, "category") == "AUTH").ToList();
        if (auth.Count == 0) W("_none captured_");
        else
        {
            foreach (var g in auth.GroupBy(e => RawStr(e, "_provider")).OrderByDescending(g => g.Count()))
            {
                W($"### {g.Key} ×{g.Count()}");
                var targets = g.Select(e => RawStr(e, "TargetName"))
                               .Where(s => !string.IsNullOrEmpty(s))
                               .GroupBy(s => s).OrderByDescending(x => x.Count()).Take(10);
                foreach (var t in targets) W($"- target {LinkHost(t.Key)} ×{t.Count()}");
                var users = g.Select(e => RawStr(e, "UserName"))
                             .Where(s => !string.IsNullOrEmpty(s)).Distinct().Take(10).ToList();
                if (users.Count > 0) W($"- users: {string.Join(", ", users)}");
                W();
            }
        }

        // ---- OAuth / identity-provider activity (inferred) ----
        W("## OAuth / identity-provider activity (inferred)");
        W();
        BuildOAuth(events, W);

        // ---- other protocol categories (LDAP/RPC/SMB/HTTP) ----
        foreach (var cat in new[] { "LDAP", "RPC", "SMB", "HTTP" })
        {
            var rows = events.Where(e => Str(e, "category") == cat).ToList();
            if (rows.Count == 0) continue;
            W($"## {cat} activity");
            W();
            foreach (var g in rows.GroupBy(e => RawStr(e, "_event")).OrderByDescending(g => g.Count()).Take(15))
                W($"- `{g.Key}` ×{g.Count()}");
            W();
        }

        var report = sb.ToString();
        Console.WriteLine(report);

        var outPath = Path.ChangeExtension(path, ".analysis.md");
        File.WriteAllText(outPath, report, Encoding.UTF8);
        Console.WriteLine($"\nReport written to: {outPath}");
        return 0;
    }

    // ============================================================ security pass

    private enum Sev { Info, Med, High }

    private sealed record Finding(Sev Sev, int Pid, string Process, string Message);

    // Living-off-the-land binaries: legitimate signed tools frequently abused for
    // execution, download, recon, or persistence. A spawn alone isn't malicious,
    // but it's exactly what a triage analyst wants surfaced.
    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "certutil", "bitsadmin", "curl", "wget", "msbuild", "installutil",
        "regasm", "regsvcs", "schtasks", "at", "sc", "wmic", "net", "net1", "reg",
        "whoami", "nltest", "dsquery", "ntdsutil", "vssadmin", "esentutl", "mavinject",
        "msiexec", "hh", "ieexec", "forfiles", "pcalua", "psexec", "psexesvc",
    };

    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge", "chrome", "firefox", "iexplore", "brave", "opera", "chromium",
    };

    // Ports whose presence is worth a second look in an outbound capture.
    private static readonly Dictionary<int, string> SensitivePorts = new()
    {
        [3389] = "RDP", [445] = "SMB", [135] = "RPC-EPM", [139] = "NetBIOS",
        [88] = "Kerberos", [389] = "LDAP", [636] = "LDAPS", [5985] = "WinRM",
        [5986] = "WinRM-S", [22] = "SSH", [23] = "Telnet", [1433] = "MSSQL",
        [3306] = "MySQL", [5432] = "Postgres", [21] = "FTP",
    };

    // Directories from which a loaded module is suspicious (DLL sideloading / drops).
    private static readonly string[] RiskyModuleDirs =
        { @"\appdata\", @"\temp\", @"\downloads\", @"\public\", @"\programdata\", @"\users\public\" };

    // Substrings of file/registry paths that touch secrets or persistence.
    private static readonly string[] SensitivePathHints =
    {
        "login data", "cookies", "credentials", "id_rsa", ".ssh", ".aws", ".kube",
        "ntuser.dat", @"\sam", "ntds.dit", "lsass", "vault", "wallet", "keychain",
        "unattend", "web.config", ".npmrc", ".git-credentials", @"\.env",
    };

    private static readonly string[] SensitiveRegHints =
    {
        @"\run", @"\runonce", @"currentversion\run", "lsa", @"\sam\", "winlogon",
        "image file execution options", "schedule", "services", "userinit",
    };

    // Known identity providers / OAuth-OIDC endpoints, matched as host substrings.
    private static readonly (string needle, string provider)[] IdpHosts =
    {
        ("login.microsoftonline.com", "Microsoft Entra ID (Azure AD)"),
        ("login.windows.net", "Microsoft Entra ID"),
        ("login.microsoft.com", "Microsoft account"),
        ("login.live.com", "Microsoft account"),
        ("sts.windows.net", "Microsoft Entra STS"),
        ("accounts.google.com", "Google"),
        ("oauth2.googleapis.com", "Google OAuth"),
        ("github.com", "GitHub"),
        ("auth0.com", "Auth0"),
        ("okta.com", "Okta"),
        ("oktapreview.com", "Okta"),
        ("login.salesforce.com", "Salesforce"),
        ("appleid.apple.com", "Apple"),
        ("id.atlassian.com", "Atlassian"),
        ("slack.com", "Slack"),
        ("login.yahoo.com", "Yahoo"),
        ("facebook.com", "Facebook"),
        ("duosecurity.com", "Duo"),
        ("pingidentity.com", "Ping Identity"),
        ("onelogin.com", "OneLogin"),
    };

    // Generic host hints when the host isn't one of the named providers above.
    private static readonly string[] IdpHostHints =
        { "oauth", "openid", "sso.", "auth.", "login.", "idp.", "sts.", "identity." };

    // OAuth/OIDC URL path markers.
    private static readonly string[] OAuthPaths =
        { "/oauth", "/authorize", "/token", "/connect/token", "/login/oauth",
          "/.well-known/openid-configuration", "/as/token.oauth2", "/v2.0/token", "/o/oauth2" };

    /// <summary>Classify a hostname as an identity provider, or null if it isn't one.</summary>
    private static string? IdpOf(string host)
    {
        if (string.IsNullOrEmpty(host)) return null;
        var low = host.ToLowerInvariant();
        foreach (var (needle, provider) in IdpHosts)
            if (low.Contains(needle)) return provider;
        foreach (var hint in IdpHostHints)
            if (low.Contains(hint)) return "identity endpoint (heuristic)";
        return null;
    }

    private static bool IsOAuthUrl(string url)
    {
        var low = url.ToLowerInvariant();
        return OAuthPaths.Any(low.Contains);
    }

    private static List<Finding> CollectFindings(
        List<Dictionary<string, JsonElement>> events, Dictionary<string, string> ipToHost)
    {
        var f = new List<Finding>();

        // --- process launches: LOLBins, browser-with-URL, embedded URLs ---
        foreach (var e in events.Where(e => Str(e, "category") == "PROC"
                                            && Str(e, "summary").StartsWith("start")))
        {
            int pid = (int)Num(e, "pid");
            var name = Str(e, "process");
            var cmd = Str(e, "commandLine");

            if (LolBins.Contains(name))
                f.Add(new(Sev.Med, pid, name, $"LOLBin launched — `{Trunc(cmd, 120)}`"));

            foreach (var url in ExtractUrls(cmd).Take(3))
                f.Add(new(Browsers.Contains(name) ? Sev.Info : Sev.Med, pid, name,
                    $"launched with URL {LinkUrl(url)}"));
        }

        // --- network: direct-to-IP (no DNS), sensitive ports ---
        var sensSeen = new HashSet<string>();
        foreach (var e in events.Where(e => Str(e, "category") == "NET"
                                            && Str(e, "kind") == "tcp-connect"))
        {
            var ip = Str(e, "remote");
            if (string.IsNullOrEmpty(ip)) continue;
            int port = (int)Num(e, "port");
            int pid = (int)Num(e, "pid");
            var name = Str(e, "process");
            var key = $"{ip}:{port}:{pid}";
            if (!sensSeen.Add(key)) continue;

            if (SensitivePorts.TryGetValue(port, out var svc))
                f.Add(new(Sev.Med, pid, name, $"connection to {svc} port — `{ip}:{port}`"));

            if (!IsPrivate(ip) && !ipToHost.ContainsKey(ip))
                f.Add(new(Sev.Med, pid, name,
                    $"outbound to public IP with no preceding DNS — `{ip}:{port}` (direct-IP / possible hardcoded endpoint)"));
        }

        // --- large outbound volume per (pid, remote): possible exfil / bulk upload ---
        const double OutboundFlag = 5 * 1024 * 1024; // 5 MB sent to one endpoint
        var outbound = events
            .Where(e => Str(e, "category") == "NET" && IsSend(Str(e, "kind"))
                        && !string.IsNullOrEmpty(Str(e, "remote")))
            .GroupBy(e => ((int)Num(e, "pid"), Str(e, "process"), Str(e, "remote")))
            .Select(g => (g.Key, Sent: g.Sum(x => Num(x, "bytes"))))
            .Where(x => x.Sent >= OutboundFlag);
        foreach (var (key, sent) in outbound)
        {
            var (pid, proc, ip) = key;
            var dest = ipToHost.TryGetValue(ip, out var h) ? $"{h} ({ip})" : ip;
            f.Add(new(IsPrivate(ip) ? Sev.Info : Sev.Med, pid, proc,
                $"large outbound transfer — {Human(sent)} sent to {dest}"));
        }

        // --- modules loaded from risky directories ---
        foreach (var e in events.Where(e => Str(e, "category") == "IMG"))
        {
            var img = Str(e, "image");
            var low = img.ToLowerInvariant();
            if (RiskyModuleDirs.Any(low.Contains))
                f.Add(new(Sev.Med, (int)Num(e, "pid"), Str(e, "process"),
                    $"module loaded from non-system path — `{Trunc(img, 110)}`"));
        }

        // --- sensitive file access ---
        foreach (var e in events.Where(e => Str(e, "category") == "FILE"))
        {
            var p = Str(e, "path").ToLowerInvariant();
            if (SensitivePathHints.Any(p.Contains))
                f.Add(new(Sev.High, (int)Num(e, "pid"), Str(e, "process"),
                    $"accessed sensitive file — `{Trunc(Str(e, "path"), 110)}`"));
        }

        // --- sensitive registry access ---
        foreach (var e in events.Where(e => Str(e, "category") == "REG"))
        {
            var s = Str(e, "summary").ToLowerInvariant();
            if (SensitiveRegHints.Any(s.Contains))
                f.Add(new(Sev.Med, (int)Num(e, "pid"), Str(e, "process"),
                    $"touched sensitive registry key — `{Trunc(Str(e, "summary"), 110)}`"));
        }

        // --- identity-provider / OAuth endpoints (inferred from host + URL path) ---
        foreach (var e in events.Where(e => Str(e, "category") == "DNS"))
        {
            var host = RawStr(e, "QueryName");
            var idp = IdpOf(host);
            if (idp != null)
                f.Add(new(Sev.Info, (int)Num(e, "pid"), Str(e, "process"),
                    $"identity provider contacted — {idp} (`{host}`)"));
        }
        foreach (var e in events)
            foreach (var u in ExtractUrls(Str(e, "commandLine")))
                if (IsOAuthUrl(u))
                    f.Add(new(Sev.Info, (int)Num(e, "pid"), Str(e, "process"),
                        $"OAuth/OIDC URL — {LinkUrl(u)}"));

        // --- NTLM usage (weaker than Kerberos; relay risk) ---
        var ntlm = events.Count(e => Str(e, "category") == "AUTH"
                                     && RawStr(e, "_provider").Contains("NTLM", StringComparison.OrdinalIgnoreCase));
        if (ntlm > 0)
            f.Add(new(Sev.Info, 0, "lsass",
                $"NTLM authentication observed ×{ntlm} (system-wide; prefer Kerberos, watch for relay)"));

        // --- de-duplicate identical findings, keep a count ---
        return f.GroupBy(x => (x.Sev, x.Pid, x.Process, x.Message))
                .Select(g => g.Count() > 1
                    ? g.First() with { Message = $"{g.First().Message} ×{g.Count()}" }
                    : g.First())
                .ToList();
    }

    private static string SevTag(Sev s) => s switch
    {
        Sev.High => "🔴 HIGH",
        Sev.Med => "🟠 MED",
        _ => "🔵 INFO",
    };

    // ============================================================== per-PID view

    private static void BuildPerPid(
        List<Dictionary<string, JsonElement>> events, Dictionary<string, string> ipToHost, Action<string> W)
    {
        // Only events that can be attributed to a real target PID (kernel + in-process
        // providers). Broker AUTH/RPCSS events carry lsass/service PIDs and are covered
        // in their own sections, so exclude them here.
        var attributable = events
            .Where(e => Str(e, "category") is "PROC" or "NET" or "DNS" or "IMG" or "FILE" or "REG"
                        || Bool(e, "attributedToTarget"))
            .Where(e => Num(e, "pid") > 0)
            .ToList();

        if (attributable.Count == 0) { W("_no attributable per-process events_"); W(""); return; }

        // pid -> friendly name. A PROC "start" record is authoritative; otherwise
        // take the first non-empty name (ProcessStop can carry an empty name and
        // must not clobber a good one).
        var nameOf = new Dictionary<int, string>();
        foreach (var e in attributable)
        {
            int pid = (int)Num(e, "pid");
            var n = Str(e, "process");
            if (n.Length == 0) continue;
            bool isStart = Str(e, "category") == "PROC" && Str(e, "summary").StartsWith("start");
            if (isStart || !nameOf.ContainsKey(pid)) nameOf[pid] = n;
        }

        // parent / command line from PROC starts.
        var meta = new Dictionary<int, (int parent, string cmd)>();
        foreach (var e in attributable.Where(e => Str(e, "category") == "PROC"
                                                  && Str(e, "summary").StartsWith("start")))
            meta[(int)Num(e, "pid")] = ((int)Num(e, "parentPid"), Str(e, "commandLine"));

        foreach (var grp in attributable.GroupBy(e => (int)Num(e, "pid"))
                                        .OrderByDescending(g => g.Count()))
        {
            int pid = grp.Key;
            var name = nameOf.TryGetValue(pid, out var nm) ? nm : $"pid{pid}";
            var header = $"### {name} (PID {pid})";
            if (meta.TryGetValue(pid, out var m)) header += $" — child of {m.parent}";
            W(header);
            if (meta.TryGetValue(pid, out var m2) && m2.cmd.Length > 0)
                W($"`{Trunc(m2.cmd, 160)}`");
            W("");

            // counts per category
            var cats = grp.GroupBy(e => Str(e, "category"))
                          .OrderByDescending(g => g.Count())
                          .Select(g => $"{g.Key}×{g.Count()}");
            W($"- Activity: {string.Join("  ", cats)}");

            // top endpoints
            var eps = grp.Where(e => Str(e, "category") == "NET" && !string.IsNullOrEmpty(Str(e, "remote")))
                         .GroupBy(e => $"{Str(e, "remote")}:{Str(e, "port")}")
                         .Select(g => new
                         {
                             Key = g.Key,
                             Ip = Str(g.First(), "remote"),
                             Sent = g.Where(x => IsSend(Str(x, "kind"))).Sum(x => Num(x, "bytes")),
                             Recv = g.Where(x => IsRecv(Str(x, "kind"))).Sum(x => Num(x, "bytes")),
                         })
                         .OrderByDescending(x => x.Sent)
                         .Take(8)
                         .ToList();
            if (eps.Count > 0)
            {
                var totalSent = eps.Sum(x => x.Sent);
                W($"- Endpoints (↑{Human(totalSent)} sent total):");
                foreach (var ep in eps)
                {
                    var host = ipToHost.TryGetValue(ep.Ip, out var h) ? $" ({LinkHost(h)})" : "";
                    W($"    - `{ep.Key}`{host} — ↑{Human(ep.Sent)} / ↓{Human(ep.Recv)}");
                }
            }

            // DNS queries
            var queries = grp.Where(e => Str(e, "category") == "DNS")
                             .Select(e => RawStr(e, "QueryName"))
                             .Where(q => !string.IsNullOrEmpty(q))
                             .Distinct().OrderBy(q => q).ToList();
            if (queries.Count > 0)
                W($"- DNS ({queries.Count}): {string.Join(", ", queries.Take(20).Select(LinkHost))}");

            // notable modules (non-system path)
            var mods = grp.Where(e => Str(e, "category") == "IMG")
                          .Select(e => Str(e, "image"))
                          .Where(i => RiskyModuleDirs.Any(i.ToLowerInvariant().Contains))
                          .Distinct().ToList();
            if (mods.Count > 0)
            {
                W("- Modules from non-system paths:");
                foreach (var im in mods.Take(10)) W($"    - `{Trunc(im, 120)}`");
            }

            W("");
        }
    }

    // ======================================================== web destinations

    private static void BuildWebDestinations(
        List<Dictionary<string, JsonElement>> events, Dictionary<string, string> ipToHost, Action<string> W)
    {
        // Explicit URLs (HTTP provider fields + command-line arguments).
        var urls = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events)
        {
            foreach (var key in new[] { "URL", "Url", "Uri" })
            {
                var u = RawStr(e, key);
                if (u.StartsWith("http", StringComparison.OrdinalIgnoreCase)) urls.Add(u);
            }
            foreach (var u in ExtractUrls(Str(e, "commandLine"))) urls.Add(u);
        }

        // Hostnames contacted: DNS query names + TLS SNI (Schannel TargetName).
        var hosts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events.Where(e => Str(e, "category") == "DNS"))
        {
            var q = RawStr(e, "QueryName");
            if (!string.IsNullOrEmpty(q)) hosts.Add(q);
        }
        foreach (var e in events.Where(e => Str(e, "category") == "AUTH"))
        {
            var t = RawStr(e, "TargetName");
            if (t.Contains('.') && !t.Contains(' ')) hosts.Add(t);
        }

        if (urls.Count == 0 && hosts.Count == 0) { W("_no URLs or hostnames observed_"); W(""); return; }

        if (urls.Count > 0)
        {
            W("**Explicit URLs**");
            foreach (var u in urls) W($"- {LinkUrl(u)}");
            W("");
        }
        if (hosts.Count > 0)
        {
            W("**Hosts contacted** (DNS / TLS SNI — click to open)");
            foreach (var h in hosts)
            {
                var ips = ipToHost.Where(kv => kv.Value.Equals(h, StringComparison.OrdinalIgnoreCase))
                                  .Select(kv => kv.Key).Distinct().ToList();
                W($"- {LinkHost(h)}" + (ips.Count > 0 ? $" → {string.Join(", ", ips)}" : ""));
            }
            W("");
        }
    }

    // ============================================================ OAuth / IdP

    private static void BuildOAuth(List<Dictionary<string, JsonElement>> events, Action<string> W)
    {
        W("> OAuth/OIDC runs **inside the encrypted TLS body** — ETW cannot read tokens, "
          + "scopes, grant types, or the code/token exchange. The endpoints below are "
          + "inferred from DNS names, TLS SNI, and command-line URLs: they show *which* "
          + "identity providers were reached, not the authentication itself.");
        W("");

        // provider -> set of "host (pid name)" observations.
        var hits = new SortedDictionary<string, SortedSet<string>>();
        void Add(string provider, string detail)
        {
            if (!hits.TryGetValue(provider, out var set))
                hits[provider] = set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(detail);
        }

        foreach (var e in events.Where(e => Str(e, "category") == "DNS"))
        {
            var host = RawStr(e, "QueryName");
            var idp = IdpOf(host);
            if (idp != null) Add(idp, $"{LinkHost(host)} _(DNS, pid {(int)Num(e, "pid")} {Str(e, "process")})_");
        }
        foreach (var e in events.Where(e => Str(e, "category") == "AUTH"))
        {
            var host = RawStr(e, "TargetName");
            var idp = IdpOf(host);
            if (idp != null) Add(idp, $"{LinkHost(host)} _(TLS SNI, broker)_");
        }
        foreach (var e in events)
            foreach (var u in ExtractUrls(Str(e, "commandLine")))
                if (IsOAuthUrl(u) || IdpOf(u) != null)
                    Add(IdpOf(u) ?? "OAuth/OIDC URL", $"{LinkUrl(u)} _(cmdline, pid {(int)Num(e, "pid")})_");

        if (hits.Count == 0) { W("_no OAuth / identity-provider endpoints observed_"); W(""); return; }

        foreach (var (provider, set) in hits)
        {
            W($"**{provider}**");
            foreach (var d in set) W($"- {d}");
            W("");
        }
    }

    // ================================================================ DNS map

    private static Dictionary<string, string> BuildDnsMap(List<Dictionary<string, JsonElement>> events)
    {
        var ipToHost = new Dictionary<string, string>();
        foreach (var e in events.Where(e => Str(e, "category") == "DNS"))
        {
            var name = RawStr(e, "QueryName");
            var results = RawStr(e, "QueryResults");
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(results)) continue;
            foreach (var ip in ExtractIps(results))
                ipToHost[ip] = name; // last writer wins; fine for triage
        }
        return ipToHost;
    }

    // =============================================================== proc tree

    private static void BuildProcessTree(List<Dictionary<string, JsonElement>> events, Action<string> W)
    {
        var starts = events.Where(e => Str(e, "category") == "PROC" && Str(e, "summary").StartsWith("start"));
        var nodes = new Dictionary<int, (string name, int parent, string cmd)>();
        foreach (var e in starts)
        {
            int pid = (int)Num(e, "pid");
            int parent = (int)Num(e, "parentPid");
            var name = Str(e, "process");
            var cmd = Str(e, "commandLine");
            nodes[pid] = (name, parent, cmd);
        }

        if (nodes.Count == 0) { W("_no child process launches captured (roots were already running)_"); W(""); return; }

        var childrenOf = nodes.GroupBy(n => n.Value.parent)
                              .ToDictionary(g => g.Key, g => g.Select(x => x.Key).ToList());
        var roots = nodes.Keys.Where(pid => !nodes.ContainsKey(nodes[pid].parent)).OrderBy(x => x).ToList();

        void Recurse(int pid, int depth)
        {
            var (name, _, cmd) = nodes[pid];
            var indent = new string(' ', depth * 2);
            var flag = LolBins.Contains(name) ? " ⚠️LOLBin" : "";
            var shortCmd = Trunc(cmd, 90);
            W($"{indent}- **{name}** ({pid}){flag} `{shortCmd}`");
            if (childrenOf.TryGetValue(pid, out var kids))
                foreach (var c in kids.OrderBy(x => x)) Recurse(c, depth + 1);
        }
        foreach (var r in roots) Recurse(r, 0);
        W("");
    }

    // ============================================================ link helpers

    private static readonly Regex UrlRx =
        new(@"https?://[^\s""'<>|]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static IEnumerable<string> ExtractUrls(string text)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (Match m in UrlRx.Matches(text))
            yield return m.Value.TrimEnd('.', ',', ')', ']', '}', '"', '\'', ';');
    }

    /// <summary>Render a URL as a clickable markdown link.</summary>
    private static string LinkUrl(string url) => $"[{url}]({url})";

    /// <summary>Render a bare hostname as a clickable https link.</summary>
    private static string LinkHost(string host)
    {
        if (string.IsNullOrEmpty(host)) return "";
        return host.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? $"[{host}]({host})"
            : $"[{host}](https://{host})";
    }

    private static string EndpointNote(string ip, string port, bool hasHost)
    {
        var notes = new List<string>();
        if (int.TryParse(port, out var p) && SensitivePorts.TryGetValue(p, out var svc))
            notes.Add($"⚠️ {svc}");
        if (!hasHost && !IsPrivate(ip)) notes.Add("⚠️ no DNS (direct-IP)");
        else if (IsPrivate(ip)) notes.Add("internal");
        return string.Join(", ", notes);
    }

    // ============================================================ JSON helpers

    private static string Str(Dictionary<string, JsonElement> e, string key) =>
        e.TryGetValue(key, out var v) ? AsString(v) : "";

    private static double Num(Dictionary<string, JsonElement> e, string key) =>
        e.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static bool Bool(Dictionary<string, JsonElement> e, string key) =>
        e.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.True;

    /// <summary>Read a field that lives inside the nested "raw" object.</summary>
    private static string RawStr(Dictionary<string, JsonElement> e, string key)
    {
        if (e.TryGetValue("raw", out var raw) && raw.ValueKind == JsonValueKind.Object
            && raw.TryGetProperty(key, out var v))
            return AsString(v);
        return "";
    }

    private static string AsString(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? "",
        JsonValueKind.Null => "",
        JsonValueKind.Number => v.ToString(),
        _ => v.ToString(),
    };

    private static bool IsSend(string kind) => kind.EndsWith("send", StringComparison.Ordinal);
    private static bool IsRecv(string kind) => kind.EndsWith("recv", StringComparison.Ordinal);

    /// <summary>Human-readable byte count: 0 B / 942 B / 13.8 KB / 4.1 MB.</summary>
    private static string Human(double bytes)
    {
        if (bytes < 1024) return $"{bytes:n0} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024:n1} KB";
        if (bytes < 1024d * 1024 * 1024) return $"{bytes / (1024d * 1024):n1} MB";
        return $"{bytes / (1024d * 1024 * 1024):n2} GB";
    }

    private static string Trunc(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length > max ? s[..max] + "…" : s);

    /// <summary>RFC1918 / loopback / link-local / multicast — i.e. not an internet host.</summary>
    private static bool IsPrivate(string ipStr)
    {
        if (!System.Net.IPAddress.TryParse(ipStr, out var ip)) return false;
        if (System.Net.IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            if (b[0] == 10) return true;                          // 10.0.0.0/8
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12
            if (b[0] == 192 && b[1] == 168) return true;          // 192.168.0.0/16
            if (b[0] == 169 && b[1] == 254) return true;          // link-local
            if (b[0] >= 224) return true;                         // multicast / reserved
            if (b[0] == 127) return true;
            return false;
        }
        // IPv6: loopback handled above; treat link-local (fe80::/10) & ULA (fc00::/7) as private.
        return b.Length == 16 && (b[0] == 0xfe && (b[1] & 0xc0) == 0x80 || (b[0] & 0xfe) == 0xfc);
    }

    private static IEnumerable<string> ExtractIps(string results)
    {
        // DNS QueryResults look like "::ffff:1.2.3.4;1.2.3.4;type:5 example.com;"
        foreach (var part in results.Split(new[] { ';', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var token = part.StartsWith("::ffff:") ? part[7..] : part;
            if (System.Net.IPAddress.TryParse(token, out var ip)) yield return ip.ToString();
        }
    }
}
