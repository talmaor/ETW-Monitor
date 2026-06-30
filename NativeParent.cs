using System.Runtime.InteropServices;

namespace ClaudeEtwMonitor;

/// <summary>
/// Resolves a process's parent PID via NtQueryInformationProcess so we can
/// seed the tracker with descendants that were already running before the
/// trace started. (New descendants are picked up live from ETW.)
/// </summary>
internal static class NativeParent
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId; // parent PID
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        ref ProcessBasicInformation processInformation,
        int processInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public static int GetParentProcessId(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return -1;
        try
        {
            var pbi = new ProcessBasicInformation();
            int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out _);
            return status == 0 ? (int)pbi.InheritedFromUniqueProcessId : -1;
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
