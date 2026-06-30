using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeEtwMonitor;

/// <summary>
/// Watches clipboard activity and attributes paste gestures (Ctrl+V / Ctrl+Shift+V
/// / Shift+Insert) to a target process by walking the process tree.
///
/// WHY this is a separate tool from the ETW monitor: clipboard CONTENT never
/// appears in any ETW event — the bytes live in shared memory, and the paste is
/// delivered to a console app over a stdin pipe. So to actually see what text is
/// pasted into Claude we read the clipboard directly (Win32 clipboard API) and
/// catch the paste keystroke with a low-level keyboard hook. Neither needs admin.
///
/// PID SCOPING — the honest version: Claude Code is node.exe, which has no window,
/// so a paste's foreground window is always the hosting TERMINAL (Windows Terminal,
/// conhost, VS Code, …). We therefore attribute by relationship in the process
/// tree (is the focused terminal an ancestor/descendant of the target node PID?)
/// and tag each capture with a confidence level. With Windows Terminal — where the
/// shell's parent IS WindowsTerminal.exe — this is reliable; with classic conhost
/// it falls back to "a console host is focused" (low confidence). Multi-tab
/// terminals can't be disambiguated: we cannot know which tab had focus.
///
///   ClaudeEtwMonitor --clipboard --name claude
/// </summary>
internal static class ClipboardWatcher
{
    private enum Confidence { None, Low, Medium, High }

    private static IReadOnlyList<int> _targets = Array.Empty<int>();
    private static readonly Dictionary<int, string> _names = new();
    private static StreamWriter? _log;
    private static readonly object _gate = new();
    private static long _seq;           // last clipboard sequence number seen
    private static long _lastPasteTick; // debounce paste gestures
    private static string? _lastText;   // echo suppression
    private static long _lastTextTick;
    private const long EchoWindowMs = 10_000;

    public static int Run(List<Process> targets)
    {
        _targets = targets.Select(p => p.Id).ToList();
        foreach (var p in targets)
            try { _names[p.Id] = p.ProcessName; } catch { _names[p.Id] = $"pid{p.Id}"; }

        var logPath = Path.Combine(Environment.CurrentDirectory,
            $"clip-{_names[_targets[0]]}-{_targets[0]}-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");
        _log = new StreamWriter(logPath, append: false, Encoding.UTF8) { AutoFlush = true };

        Console.WriteLine("=== Clipboard / Paste Watcher ===\n");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine(
            "  This tool reads CLIPBOARD TEXT CONTENT and logs it to disk when a paste is\n" +
            "  directed at a tracked process (or a copy happens while one is focused).\n" +
            "  It is a clipboard recorder — run it only on your own machine / sessions.");
        Console.ResetColor();
        Console.WriteLine($"\nTargets:");
        foreach (var id in _targets) Console.WriteLine($"   • {_names[id]} (PID {id})");
        Console.WriteLine($"\nLogging to: {logPath}\nPress Ctrl+C to stop.\n");

        _seq = GetClipboardSequenceNumber();

        // Poll the clipboard sequence number for copies / changes (no window needed).
        using var poll = new Timer(_ => OnClipboardMaybeChanged(), null, 250, 250);

        // Low-level keyboard hook must live on a thread that pumps messages.
        _hookProc = KeyboardProc; // keep delegate alive (no GC)
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _hookProc, GetModuleHandle(null), 0);
        if (_hook == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to install keyboard hook (err {Marshal.GetLastWin32Error()}). " +
                              "Copy detection still works; paste-gesture detection won't.");
        }

        // Mouse hook catches right-click paste in console hosts (no keystroke fires).
        _mouseProc = MouseProc;
        _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);
        if (_mouseHook == IntPtr.Zero)
            Console.WriteLine($"Failed to install mouse hook (err {Marshal.GetLastWin32Error()}). " +
                              "Right-click paste won't be detected.");

        Console.CancelKeyPress += (_, e) => { e.Cancel = true; PostQuitMessage(0); };

        // Message loop (drives the LL hook).
        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }

        if (_hook != IntPtr.Zero) UnhookWindowsHookEx(_hook);
        if (_mouseHook != IntPtr.Zero) UnhookWindowsHookEx(_mouseHook);
        _log.Dispose();
        Console.WriteLine("\nStopped.");
        return 0;
    }

    // --------------------------------------------------------------- detection

    private static void OnClipboardMaybeChanged()
    {
        var cur = GetClipboardSequenceNumber();
        if (cur == _seq) return;
        _seq = cur;

        int fgPid = ForegroundPid(out var fgName);
        var conf = Attribute(fgPid, out var target, out var reason);
        // A copy is only interesting if a tracked terminal is focused — otherwise
        // it's unrelated clipboard churn from other apps. This keeps us PID-scoped.
        if (conf == Confidence.None) return;

        var (text, formats, files) = ReadClipboard();
        Record("clipboard-update", "copy/out", fgPid, fgName, target, conf, reason, text, formats, files);
    }

    private static IntPtr KeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
        {
            var info = Marshal.PtrToStructure<KbDllHookStruct>(lParam);
            int vk = (int)info.vkCode;
            bool ctrl = Down(VK_CONTROL);
            bool shift = Down(VK_SHIFT);

            // Ctrl+V, Ctrl+Shift+V (terminal paste), or Shift+Insert.
            bool paste = (vk == VK_V && ctrl) || (vk == VK_INSERT && shift && !ctrl);
            if (paste)
            {
                long now = Environment.TickCount64;
                if (now - _lastPasteTick > 200) // debounce key-repeat
                {
                    _lastPasteTick = now;
                    HandlePasteGesture(vk == VK_INSERT ? "shift-insert" : (shift ? "ctrl-shift-v" : "ctrl-v"));
                }
            }
        }
        return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private static IntPtr MouseProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_RBUTTONDOWN)
        {
            long now = Environment.TickCount64;
            if (now - _lastPasteTick > 200)
            {
                _lastPasteTick = now;
                // Only treat right-click as paste inside a console host — in GUI apps
                // (incl. the Chromium Claude desktop app) right-click opens a menu.
                HandlePasteGesture("right-click", requireTerminalFg: true);
            }
        }
        return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
    }

    private static void HandlePasteGesture(string gesture, bool requireTerminalFg = false)
    {
        int fgPid = ForegroundPid(out var fgName);
        if (requireTerminalFg && !IsTerminalish(fgName)) return;
        var conf = Attribute(fgPid, out var target, out var reason);
        if (conf == Confidence.None)
        {
            // Paste into something unrelated to the target — respect scoping: do NOT
            // read or persist the content; just note it on the console.
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] paste ({gesture}) into {fgName}({fgPid}) — not a target, content not captured");
            Console.ResetColor();
            return;
        }

        // At Ctrl+V-down the clipboard already holds the to-be-pasted data.
        var (text, formats, files) = ReadClipboard();
        Record(gesture, "paste/in", fgPid, fgName, target, conf, reason, text, formats, files);
    }

    // ------------------------------------------------------------- attribution

    /// <summary>
    /// Decide whether a foreground PID's input is going to one of our targets,
    /// via the process tree. Returns the best confidence across all targets.
    /// </summary>
    private static Confidence Attribute(int fgPid, out int matchedTarget, out string reason)
    {
        matchedTarget = -1;
        reason = "no foreground/target relationship";
        if (fgPid <= 0) return Confidence.None;

        var fgChain = AncestorChain(fgPid);
        var best = Confidence.None;

        foreach (var t in _targets)
        {
            var tChain = AncestorChain(t);

            Confidence c;
            string why;
            if (fgPid == t) { c = Confidence.High; why = "foreground IS the target"; }
            else if (tChain.Contains(fgPid)) { c = Confidence.High; why = $"target is descendant of focused {NameOf(fgPid)}({fgPid})"; }
            else if (fgChain.Contains(t)) { c = Confidence.High; why = $"focused window is descendant of target"; }
            else
            {
                var common = tChain.Intersect(fgChain).FirstOrDefault(x => x > 0);
                if (common != 0 && IsTerminalish(NameOf(common)))
                { c = Confidence.Medium; why = $"share terminal ancestor {NameOf(common)}({common})"; }
                else if (IsTerminalish(NameOf(fgPid)))
                { c = Confidence.Low; why = $"a console host ({NameOf(fgPid)}) is focused (tree link unproven)"; }
                else { c = Confidence.None; why = "unrelated foreground"; }
            }

            if (c > best) { best = c; matchedTarget = (c == Confidence.Low) ? _targets[0] : t; reason = why; }
        }
        return best;
    }

    private static List<int> AncestorChain(int pid)
    {
        var chain = new List<int>();
        var seen = new HashSet<int>();
        int cur = pid, depth = 0;
        while (cur > 0 && depth++ < 16 && seen.Add(cur))
        {
            chain.Add(cur);
            cur = NativeParent.GetParentProcessId(cur);
        }
        return chain;
    }

    private static readonly string[] Terminalish =
    {
        "windowsterminal", "wt", "openconsole", "conhost", "powershell", "pwsh",
        "cmd", "bash", "wsl", "wslhost", "code", "cursor", "conemu", "mintty",
        "alacritty", "wezterm", "tabby", "hyper", "explorer",
    };

    private static bool IsTerminalish(string name) =>
        Terminalish.Any(t => name.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static string NameOf(int pid)
    {
        if (pid <= 0) return "?";
        if (_names.TryGetValue(pid, out var n)) return n;
        try { n = Process.GetProcessById(pid).ProcessName; } catch { n = $"pid{pid}"; }
        _names[pid] = n;
        return n;
    }

    private static int ForegroundPid(out string name)
    {
        var hwnd = GetForegroundWindow();
        if (hwnd == IntPtr.Zero) { name = "?"; return -1; }
        GetWindowThreadProcessId(hwnd, out var pid);
        name = NameOf(pid);
        return pid;
    }

    // --------------------------------------------------------------- clipboard

    private static (string? text, string formats, List<string> files) ReadClipboard()
    {
        var files = new List<string>();
        string formats = "";
        for (int attempt = 0; attempt < 6; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    formats = string.Join(",", EnumFormats());

                    // Files (CF_HDROP) — "content" of a file copy/paste.
                    if (IsClipboardFormatAvailable(CF_HDROP))
                    {
                        var h = GetClipboardData(CF_HDROP);
                        if (h != IntPtr.Zero)
                        {
                            uint n = DragQueryFile(h, 0xFFFFFFFF, null, 0);
                            for (uint i = 0; i < n; i++)
                            {
                                var sbf = new StringBuilder(260);
                                DragQueryFile(h, i, sbf, sbf.Capacity);
                                files.Add(sbf.ToString());
                            }
                        }
                    }

                    // Unicode text.
                    if (IsClipboardFormatAvailable(CF_UNICODETEXT))
                    {
                        var h = GetClipboardData(CF_UNICODETEXT);
                        if (h != IntPtr.Zero)
                        {
                            var p = GlobalLock(h);
                            if (p != IntPtr.Zero)
                            {
                                try { return (Marshal.PtrToStringUni(p), formats, files); }
                                finally { GlobalUnlock(h); }
                            }
                        }
                    }
                    return (null, formats, files);
                }
                finally { CloseClipboard(); }
            }
            Thread.Sleep(20); // clipboard momentarily owned by another app
        }
        return (null, formats, files);
    }

    private static IEnumerable<string> EnumFormats()
    {
        var list = new List<string>();
        uint fmt = 0;
        while ((fmt = EnumClipboardFormats(fmt)) != 0)
        {
            var name = fmt switch
            {
                CF_UNICODETEXT => "CF_UNICODETEXT",
                CF_TEXT => "CF_TEXT",
                CF_HDROP => "CF_HDROP",
                2 => "CF_BITMAP",
                8 => "CF_DIB",
                _ => NamedFormat(fmt),
            };
            list.Add(name);
        }
        return list;
    }

    private static string NamedFormat(uint fmt)
    {
        var sb = new StringBuilder(128);
        return GetClipboardFormatName(fmt, sb, sb.Capacity) > 0 ? sb.ToString() : $"fmt#{fmt}";
    }

    // -------------------------------------------------- sensitive-content scan

    // Lightweight DLP: tag clipboard text that looks like secrets / PII / PHI.
    // Pattern-based and best-effort — meant to surface "you just pasted something
    // sensitive into an AI tool", not to be an authoritative classifier.
    private static readonly (string tag, Regex rx)[] SensitivePatterns =
    {
        ("aws-key",      new(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled)),
        ("github-token", new(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", RegexOptions.Compiled)),
        ("slack-token",  new(@"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", RegexOptions.Compiled)),
        ("google-key",   new(@"\bAIza[0-9A-Za-z_\-]{35}\b", RegexOptions.Compiled)),
        ("jwt",          new(@"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", RegexOptions.Compiled)),
        ("private-key",  new(@"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", RegexOptions.Compiled)),
        ("secret-assignment", new(@"(?i)\b(password|passwd|pwd|api[_-]?key|secret|client[_-]?secret|token|bearer)\b\s*[:=]\s*\S", RegexOptions.Compiled)),
        ("ssn",          new(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled)),
        ("email",        new(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled)),
        ("ip-address",   new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)),
    };

    private static readonly Regex CardLike = new(@"\b(?:\d[ -]?){13,19}\b", RegexOptions.Compiled);

    private static readonly string[] PhiKeywords =
    {
        "patient", "medical record", "mrn", "diagnosis", "prescription",
        "date of birth", "dob", "icd-", "health record", "lab result",
    };

    private static List<string> ScanSensitive(string? text)
    {
        var hits = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text)) return new();

        foreach (var (tag, rx) in SensitivePatterns)
            if (rx.IsMatch(text)) hits.Add(tag);

        var low = text.ToLowerInvariant();
        if (PhiKeywords.Any(low.Contains)) hits.Add("phi/medical");

        // Credit-card: candidate digit runs validated with the Luhn checksum to
        // cut false positives from order numbers / long IDs.
        foreach (Match m in CardLike.Matches(text))
        {
            var digits = new string(m.Value.Where(char.IsDigit).ToArray());
            if (digits.Length is >= 13 and <= 19 && Luhn(digits)) { hits.Add("credit-card"); break; }
        }
        return hits.ToList();
    }

    private static bool Luhn(string digits)
    {
        int sum = 0; bool dbl = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    // ------------------------------------------------------------------ output

    private static void Record(string gesture, string direction, int fgPid, string fgName,
        int target, Confidence conf, string reason, string? text, string formats, List<string> files)
    {
        // Echo suppression: a Chromium/Electron app (e.g. the Claude desktop app)
        // re-writes the clipboard with an HTML-normalized copy after a paste, which
        // bumps the sequence number and re-surfaces as a "copy/out". Drop a copy
        // whose text we just logged. Pastes are deliberate user actions — never
        // deduped, even if repeated.
        long now = Environment.TickCount64;
        bool isCopy = direction.StartsWith("copy");
        if (isCopy && text != null && text == _lastText && now - _lastTextTick < EchoWindowMs)
            return;
        if (text != null) { _lastText = text; _lastTextTick = now; }

        var sensitive = ScanSensitive(text);

        var rec = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"),
            ["gesture"] = gesture,
            ["direction"] = direction,
            ["foregroundPid"] = fgPid,
            ["foregroundProcess"] = fgName,
            ["attributedTarget"] = target > 0 ? target : null,
            ["confidence"] = conf.ToString(),
            ["why"] = reason,
            ["textLength"] = text?.Length ?? 0,
            ["formats"] = formats,
            ["files"] = files.Count > 0 ? files : null,
            ["sensitive"] = sensitive.Count > 0 ? sensitive : null,
            ["text"] = text,
        };

        string json;
        try { json = JsonSerializer.Serialize(rec, JsonOpts); }
        catch (Exception ex) { json = $"{{\"ts\":\"{rec["ts"]}\",\"_serializeError\":\"{ex.Message}\"}}"; }

        lock (_gate)
        {
            bool flagged = sensitive.Count > 0;
            Console.ForegroundColor = flagged ? ConsoleColor.Red
                : direction.StartsWith("paste") ? ConsoleColor.Cyan : ConsoleColor.DarkCyan;
            var mark = flagged ? "⚠ " : "  ";
            Console.Write($"{mark}[{DateTime.Now:HH:mm:ss}] {direction,-9} {gesture,-12}");
            Console.ResetColor();
            var who = target > 0 ? $"{NameOf(target)}({target})" : fgName;
            var tags = flagged ? $"  SENSITIVE[{string.Join(",", sensitive)}]" : "";
            if (flagged) Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($" → {who} [{conf}]{tags}  {Preview(text, files)}");
            Console.ResetColor();
            _log!.WriteLine(json);
        }
    }

    private static string Preview(string? text, List<string> files)
    {
        if (files.Count > 0) return $"{files.Count} file(s): {string.Join("; ", files.Take(3))}";
        if (string.IsNullOrEmpty(text)) return "(no text)";
        var oneLine = text.Replace("\r", " ").Replace("\n", " ");
        var shown = oneLine.Length > 100 ? oneLine[..100] + "…" : oneLine;
        return $"{text.Length} chars: \"{shown}\"";
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    // -------------------------------------------------------------- P/Invoke

    private const int WH_KEYBOARD_LL = 13, WH_MOUSE_LL = 14;
    private const int WM_KEYDOWN = 0x0100, WM_SYSKEYDOWN = 0x0104, WM_RBUTTONDOWN = 0x0204;
    private const int VK_CONTROL = 0x11, VK_SHIFT = 0x10, VK_V = 0x56, VK_INSERT = 0x2D;
    private const uint CF_TEXT = 1, CF_UNICODETEXT = 13, CF_HDROP = 15;

    private static IntPtr _hook, _mouseHook;
    private static LowLevelKeyboardProc? _hookProc, _mouseProc;
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KbDllHookStruct { public uint vkCode, scanCode, flags, time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public int x, y; }

    private static bool Down(int vk) => (GetAsyncKeyState(vk) & 0x8000) != 0;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);
    [DllImport("user32.dll")] private static extern int GetMessage(out Msg lpMsg, IntPtr hWnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Msg lpMsg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref Msg lpMsg);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string? name);

    [DllImport("user32.dll")] private static extern bool OpenClipboard(IntPtr hWndNewOwner);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern IntPtr GetClipboardData(uint uFormat);
    [DllImport("user32.dll")] private static extern bool IsClipboardFormatAvailable(uint format);
    [DllImport("user32.dll")] private static extern uint EnumClipboardFormats(uint format);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClipboardFormatName(uint format, StringBuilder lpsz, int cch);
    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalLock(IntPtr hMem);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(IntPtr hMem);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint DragQueryFile(IntPtr hDrop, uint iFile, StringBuilder? lpszFile, int cch);
}
