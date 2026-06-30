using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;

namespace ClaudeEtwMonitor;

/// <summary>
/// Renders captured events to the console (color-coded, concise) and, in
/// parallel, appends them as JSON lines to a log file. The console line is a
/// summary; the JSONL record carries the COMPLETE event (every payload field +
/// ETW header metadata) under "raw" so later analysis loses nothing.
/// </summary>
internal sealed class EventLogger : IDisposable
{
    private readonly StreamWriter _jsonl;
    private readonly object _gate = new();
    private long _count;

    public EventLogger(string logPath)
    {
        _jsonl = new StreamWriter(logPath, append: false, Encoding.UTF8) { AutoFlush = true };
        LogPath = logPath;
    }

    public string LogPath { get; }
    public long Count => Interlocked.Read(ref _count);

    public void Write(string category, int pid, string procName, string summary,
                      IReadOnlyDictionary<string, object?>? fields = null,
                      TraceEvent? raw = null)
    {
        Interlocked.Increment(ref _count);

        var record = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"),
            ["category"] = category,
            ["pid"] = pid,
            ["process"] = procName,
            ["summary"] = summary,
        };
        if (fields != null)
            foreach (var kv in fields) record[kv.Key] = kv.Value;

        if (raw != null)
            record["raw"] = EventDecode.FullCapture(raw);

        string json;
        try
        {
            json = JsonSerializer.Serialize(record, JsonOpts);
        }
        catch (Exception ex)
        {
            // Never let one unserializable event tear down the trace session.
            json = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["ts"] = record["ts"],
                ["category"] = category,
                ["pid"] = pid,
                ["process"] = procName,
                ["summary"] = summary,
                ["_serializeError"] = ex.Message,
            }, JsonOpts);
        }

        lock (_gate)
        {
            Console.ForegroundColor = ColorFor(category);
            Console.Write($"[{DateTime.Now:HH:mm:ss.fff}] {category,-5}");
            Console.ResetColor();
            Console.WriteLine($" {procName}({pid})  {summary}");

            _jsonl.WriteLine(json);
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        // IPAddress and similar render via ToString through the converter chain;
        // keep output compact and resilient to odd payload values.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static ConsoleColor ColorFor(string category) => category switch
    {
        "PROC" => ConsoleColor.Yellow,
        "NET" => ConsoleColor.Green,
        "DNS" => ConsoleColor.Magenta,
        "AUTH" => ConsoleColor.Red,
        "LDAP" => ConsoleColor.DarkMagenta,
        "RPC" => ConsoleColor.Blue,
        "SMB" => ConsoleColor.DarkGreen,
        "HTTP" => ConsoleColor.Cyan,
        "FILE" => ConsoleColor.DarkCyan,
        "REG" => ConsoleColor.DarkGray,
        "IMG" => ConsoleColor.DarkBlue,
        _ => ConsoleColor.Gray,
    };

    public void Dispose() => _jsonl.Dispose();
}
