using System.Diagnostics;

namespace ClaudeEtwMonitor;

/// <summary>
/// Lists running processes and lets the user pick one OR MORE to monitor.
/// Claude Code runs as several node.exe processes, so multi-select matters:
///  - a name (e.g. "node") selects ALL matching processes
///  - a comma list of PIDs selects exactly those
/// </summary>
internal static class ProcessPicker
{
    private static readonly string[] InterestingNames =
        { "node", "claude", "claude-code", "bun", "deno" };

    // Our own PID — never monitor ourselves (our name contains "claude").
    private static readonly int Self = Environment.ProcessId;

    public static List<Process> Select(string? preselectArg)
    {
        if (!string.IsNullOrWhiteSpace(preselectArg))
        {
            var direct = ResolveMany(preselectArg);
            if (direct.Count > 0) return direct;
            Console.WriteLine($"Could not resolve '{preselectArg}', falling back to interactive picker.\n");
        }

        var procs = Process.GetProcesses()
            .Where(p => p.Id != Self && SafeHasName(p))
            .OrderByDescending(IsInteresting)
            .ThenBy(SafeName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        Console.WriteLine("Running processes (★ = likely Claude Code):\n");
        Console.WriteLine($"  {"PID",-8} {"Name",-28} Window / hint");
        Console.WriteLine(new string('-', 78));

        foreach (var p in procs)
        {
            var star = IsInteresting(p) ? "★" : " ";
            Console.ForegroundColor = IsInteresting(p) ? ConsoleColor.Cyan : ConsoleColor.Gray;
            Console.WriteLine($"{star} {p.Id,-8} {Trunc(SafeName(p), 28),-28} {Trunc(SafeWindowTitle(p), 34)}");
        }
        Console.ResetColor();

        Console.Write("\nEnter PIDs (comma-separated) OR a name to select ALL matching: ");
        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(input)) return new();

        var chosen = ResolveMany(input);
        if (chosen.Count > 1)
        {
            Console.WriteLine($"\nSelected {chosen.Count} processes:");
            foreach (var p in chosen)
                Console.WriteLine($"   PID {p.Id,-8} {SafeName(p)}");
        }
        return chosen;
    }

    /// <summary>Parse a selection token list: ints are PIDs, words are name substrings (all matches).</summary>
    private static List<Process> ResolveMany(string input)
    {
        var result = new Dictionary<int, Process>();
        foreach (var raw in input.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim();
            if (token.Length == 0) continue;

            if (int.TryParse(token, out var pid))
            {
                if (pid == Self) continue;
                try { var p = Process.GetProcessById(pid); result[p.Id] = p; } catch { }
            }
            else
            {
                foreach (var p in Process.GetProcesses()
                             .Where(p => p.Id != Self && SafeName(p).Contains(token, StringComparison.OrdinalIgnoreCase)))
                    result[p.Id] = p;
            }
        }
        return result.Values.ToList();
    }

    private static bool IsInteresting(Process p) =>
        InterestingNames.Any(n => SafeName(p).Contains(n, StringComparison.OrdinalIgnoreCase));

    private static bool SafeHasName(Process p)
    {
        try { _ = p.ProcessName; return true; } catch { return false; }
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return "?"; }
    }

    private static string SafeWindowTitle(Process p)
    {
        try { return string.IsNullOrEmpty(p.MainWindowTitle) ? "" : p.MainWindowTitle; }
        catch { return ""; }
    }

    private static string Trunc(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..(max - 1)] + "…");
}
