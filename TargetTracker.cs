using System.Collections.Concurrent;
using System.Diagnostics;

namespace ClaudeEtwMonitor;

/// <summary>
/// Maintains the set of process IDs we care about: one or more user-selected
/// roots (Claude Code typically runs several node.exe processes) plus any
/// descendants they spawn while we are tracing. ETW events are filtered against
/// this set so we only report activity from the target trees.
/// </summary>
internal sealed class TargetTracker
{
    private readonly ConcurrentDictionary<int, string> _pids = new();
    private readonly HashSet<int> _rootPids = new();

    public TargetTracker(IEnumerable<Process> roots)
    {
        foreach (var r in roots)
        {
            _rootPids.Add(r.Id);
            _pids[r.Id] = SafeName(r);
        }

        // Seed with already-running descendants of any root.
        foreach (var (childPid, childName, parentPid) in EnumerateProcessTree())
            if (_rootPids.Contains(parentPid))
                _pids[childPid] = childName;
    }

    public IReadOnlyCollection<int> RootPids => _rootPids;

    public bool IsTracked(int pid) => pid > 0 && _pids.ContainsKey(pid);

    public string NameOf(int pid) => _pids.TryGetValue(pid, out var n) ? n : "?";

    /// <summary>Called on every process-start event so children are followed.</summary>
    public bool OnProcessStart(int pid, int parentPid, string name)
    {
        if (!_pids.ContainsKey(parentPid)) return false;
        _pids[pid] = name;
        return true;
    }

    public void OnProcessStop(int pid)
    {
        if (!_rootPids.Contains(pid)) _pids.TryRemove(pid, out _);
    }

    public IReadOnlyDictionary<int, string> Snapshot() => _pids;

    private static IEnumerable<(int pid, string name, int parentPid)> EnumerateProcessTree()
    {
        foreach (var p in Process.GetProcesses())
        {
            int parent;
            try { parent = NativeParent.GetParentProcessId(p.Id); } catch { continue; }
            yield return (p.Id, SafeName(p), parent);
        }
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return "?"; }
    }
}
