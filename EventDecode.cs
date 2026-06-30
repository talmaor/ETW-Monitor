using System.Diagnostics;
using Microsoft.Diagnostics.Tracing;

namespace ClaudeEtwMonitor;

/// <summary>Caches PID -> process name so system-wide events (lsass/RPCSS) can be labelled.</summary>
internal sealed class ProcNameCache
{
    private readonly Dictionary<int, string> _cache = new();

    public string Get(int pid)
    {
        if (pid <= 0) return "?";
        if (_cache.TryGetValue(pid, out var n)) return n;
        try { n = Process.GetProcessById(pid).ProcessName; }
        catch { n = $"pid{pid}"; }
        _cache[pid] = n;
        return n;
    }
}

/// <summary>
/// Decoding of ETW events. Two levels:
///  - Decode()       : a short human summary for the console.
///  - FullCapture()  : EVERY payload field + ETW header metadata, for the log,
///                     so nothing is silently dropped.
/// </summary>
internal static class EventDecode
{
    // Fields worth surfacing in the one-line console summary, in priority order.
    private static readonly string[] Preferred =
    {
        // HTTP/URL fields (WinINet / WinHttp providers expose the full request URL)
        "URL", "Url", "Uri", "Verb", "Method", "Referer", "UserAgent", "StatusCode",
        "TargetName", "TargetServerName", "ServerName", "TargetInfo",
        "UserName", "User", "DomainName", "ClientName", "ClientDomainName",
        "PackageName", "AuthPackage", "MechanismOid",
        "QueryName", "QueryResults", "QueryType", "Address", "AddressLength",
        "DestinationName", "Endpoint", "InterfaceUuid", "ProtocolSequence",
        "NetworkAddress", "Port", "Path", "ShareName",
        "Status", "NtStatus", "ErrorCode", "Result",
    };

    public static string Decode(TraceEvent d)
    {
        var parts = new List<string>();
        foreach (var k in Preferred)
        {
            object? v;
            try { v = d.PayloadByName(k); } catch { continue; }
            if (v != null && v.ToString()!.Length > 0) parts.Add($"{k}={v}");
        }
        return parts.Count > 0 ? string.Join("  ", parts) : (TryFormatted(d) ?? "");
    }

    /// <summary>Capture the COMPLETE event: all payload fields + header metadata.</summary>
    public static Dictionary<string, object?> FullCapture(TraceEvent d)
    {
        var f = new Dictionary<string, object?>();

        foreach (var name in d.PayloadNames)
        {
            try { f[name] = Normalize(d.PayloadByName(name)); }
            catch { f[name] = "<unreadable>"; }
        }

        // ETW header / correlation metadata (prefixed so it never clashes with payload names).
        f["_provider"] = d.ProviderName;
        f["_event"] = d.EventName;
        f["_task"] = d.TaskName;
        f["_opcode"] = d.Opcode.ToString();
        f["_id"] = (int)d.ID;
        f["_version"] = d.Version;
        f["_level"] = d.Level.ToString();
        f["_keywords"] = "0x" + ((ulong)d.Keywords).ToString("x");
        f["_tid"] = d.ThreadID;
        f["_cpu"] = d.ProcessorNumber;
        f["_activityId"] = SafeGuid(() => d.ActivityID);
        f["_relatedActivityId"] = SafeGuid(() => d.RelatedActivityID);
        var msg = TryFormatted(d);
        if (msg != null) f["_message"] = msg;

        return f;
    }

    public static string? TryFormatted(TraceEvent d)
    {
        try
        {
            var msg = d.FormattedMessage;
            return string.IsNullOrWhiteSpace(msg) ? null : msg.Replace("\r", " ").Replace("\n", " ").Trim();
        }
        catch { return null; }
    }

    private static object? Normalize(object? v) => v switch
    {
        null => null,
        string s => s,
        bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal => v,
        byte[] b => HexTrunc(b),
        // Everything else (IPAddress, Guid, Enum, Address, ...) is stringified so
        // the JSON serializer never reflects over an arbitrary ETW object. (IPv4
        // IPAddress in particular throws on get_ScopeId during reflection.)
        _ => v.ToString(),
    };

    private static string HexTrunc(byte[] b)
    {
        var h = Convert.ToHexString(b);
        return h.Length > 512 ? h[..512] + "…" : h;
    }

    private static string? SafeGuid(Func<Guid> get)
    {
        try { var g = get(); return g == Guid.Empty ? null : g.ToString(); }
        catch { return null; }
    }
}
