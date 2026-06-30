namespace ClaudeEtwMonitor;

/// <summary>
/// Where a provider's events are emitted, which decides whether PID-filtering
/// to the target works:
///  - InProcess : events fire in the target's own process context (filterable).
///  - SystemWide: events fire in a broker (lsass.exe / RPCSS / services) on
///                behalf of many processes, so they carry the broker's PID and
///                cannot be cleanly attributed to the target. Captured globally.
/// </summary>
internal enum Scope { InProcess, SystemWide }

internal sealed record EtwProvider(
    string Name,
    Guid Guid,
    string Category,   // console tag: AUTH / LDAP / RPC / SMB / NET / DNS / HTTP
    Scope Scope,
    string Group,      // CLI group key that turns it on
    bool Manifest = true); // false = legacy WPP (may show raw / undecoded)

/// <summary>
/// Catalog of user-mode ETW providers, with GUIDs verified against this machine
/// via `logman query providers`. Add or remove rows here to change coverage.
/// </summary>
internal static class ProviderCatalog
{
    public static readonly EtwProvider[] All =
    {
        // === DNS (on by default) — node uses the OS resolver, so this works ===
        new("Microsoft-Windows-DNS-Client", new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"), "DNS", Scope.InProcess, "dns"),

        // === Auth / SSPI — execute in lsass.exe, captured system-wide ===
        new("Microsoft-Windows-NTLM",              new("AC43300D-5FCC-4800-8E99-1BD3F85F0320"), "AUTH", Scope.SystemWide, "auth"),
        new("Microsoft-Windows-Security-Kerberos", new("98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1"), "AUTH", Scope.SystemWide, "auth"),
        new("Microsoft-Windows-Schannel-Events",   new("91CC1150-71AA-47E2-AE18-C96E61736B6F"), "AUTH", Scope.SystemWide, "auth"),
        new("Microsoft-Windows-Security-Netlogon", new("E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC"), "AUTH", Scope.SystemWide, "auth"),
        new("Active Directory: Kerberos Client",   new("BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4"), "AUTH", Scope.InProcess,  "auth", Manifest: false),

        // === Legacy SSPI WPP providers (the classic "Security: *" set) ===
        new("Security: NTLM Authentication",     new("5BBB6C18-AA45-49B1-A15F-085F7ED0AA90"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("Security: Kerberos Authentication", new("6B510852-3583-4E2D-AFFE-A67F9F223438"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("Security: SChannel",                new("37D2C3CD-C5D4-4587-8531-4696C44244C8"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("Security: WDigest",                 new("FB6A424F-B5D6-4329-B9D5-A975B3A93EAD"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("Security: TSPkg",                   new("6165F3E2-AE38-45D4-9B23-6B4818758BD9"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("NTLM Security Protocol",            new("C92CF544-91B3-4DC0-8E11-C580339A0BF8"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("Local Security Authority (LSA)",    new("CC85922F-DB41-11D2-9244-006008269001"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),
        new("LsaSrv",                            new("199FE037-2B82-40A9-82AC-E1D46C792B99"), "AUTH", Scope.SystemWide, "auth-legacy", Manifest: false),

        // === LDAP — wldap32.dll runs in the client process (filterable) ===
        new("Microsoft-Windows-LDAP-Client", new("099614A5-5DD7-4788-8BC9-E29F43DB28FC"), "LDAP", Scope.InProcess, "ldap"),

        // === RPC — client stub in-process; RPCSS is the broker service ===
        new("Microsoft-Windows-RPC",       new("6AD52B32-D609-4BE9-AE07-CE8DAE937E39"), "RPC", Scope.InProcess,  "rpc"),
        new("Microsoft-Windows-RPCSS",     new("D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C"), "RPC", Scope.SystemWide, "rpc"),
        new("Microsoft-Windows-RPC-Events",new("F4AED7C7-A898-4627-B053-44A7CAA12FCD"), "RPC", Scope.InProcess,  "rpc"),

        // === SMB client (in-process) ===
        new("Microsoft-Windows-SMBClient", new("988C59C5-0A1C-45B6-A555-0C62276E327D"), "SMB", Scope.InProcess, "smb"),

        // === Winsock / name resolution (in-process) ===
        new("Microsoft-Windows-Winsock-NameResolution", new("55404E71-4DB9-4DEB-A5F5-8F86E46DDE56"), "NET", Scope.InProcess, "winsock"),
        new("Microsoft-Windows-Winsock-AFD",            new("E53C6823-7BB8-44BB-90DC-3F86090D48A6"), "NET", Scope.InProcess, "winsock"),
        new("Microsoft-Windows-Winsock-Sockets",        new("BDE46AEA-2357-51FE-7367-D5296F530BD1"), "NET", Scope.InProcess, "winsock"),

        // === HTTP via Windows stacks — node uses BoringSSL, NOT these. Included
        //     for completeness / child tools (curl, PowerShell, .NET) that do. ===
        new("Microsoft-Windows-WinINet", new("43D1A55C-76D6-4F7E-995C-64C711E5CAFE"), "HTTP", Scope.InProcess, "http"),
        new("Microsoft-Windows-WinHttp", new("7D44233D-3055-4B9C-BA64-0D47CA40A232"), "HTTP", Scope.InProcess, "http"),
    };

    /// <summary>Groups always enabled regardless of flags.</summary>
    public static readonly string[] DefaultGroups = { "dns" };

    /// <summary>Groups that produce system-wide (non-attributable) events.</summary>
    public static bool IsSystemWideGroup(string group) =>
        All.Any(p => p.Group == group && p.Scope == Scope.SystemWide);
}
