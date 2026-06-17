/*
 * HawkScan Windows technique rules (original).
 * Generic, behaviour-oriented detections for common Windows malware techniques:
 * AMSI/ETW evasion, Defender tampering, clipboard hijacking, credential-store
 * theft, scheduled-task persistence, and self-deletion. Conservative multi-string
 * conditions to limit false positives on legitimate software.
 */

rule HawkScan_AMSI_Bypass
{
    meta:
        description = "AMSI (Antimalware Scan Interface) bypass attempt"
        severity = "high"
        category = "defense-evasion"
    strings:
        $a = "AmsiScanBuffer" nocase
        $b = "amsiInitFailed" nocase
        $c = "amsi.dll" nocase
        $d = "AmsiUtils" nocase
        $e = "System.Management.Automation.AmsiUtils" nocase
    condition:
        ($a and $c) or $b or $e or ($c and $d)
}

rule HawkScan_ETW_Patch
{
    meta:
        description = "ETW (Event Tracing for Windows) patching to blind logging"
        severity = "high"
        category = "defense-evasion"
    strings:
        $a = "EtwEventWrite" nocase
        $b = "ntdll" nocase
        $c = "EtwEventRegister" nocase
        $log = "EtwpEventWrite" nocase
    condition:
        ($a and $b) or $log or ($c and $a)
}

rule HawkScan_Defender_Tamper
{
    meta:
        description = "Windows Defender / AV tampering"
        severity = "high"
        category = "defense-evasion"
    strings:
        $a = "DisableRealtimeMonitoring" nocase
        $b = "DisableAntiSpyware" nocase
        $c = "Set-MpPreference" nocase
        $d = "Add-MpPreference" nocase
        $e = "MpCmdRun" nocase
        $f = "ExclusionPath" nocase
    condition:
        $a or $b or ($c and ($a or $f)) or ($d and $f) or ($e and $f)
}

rule HawkScan_Clipboard_Hijacker
{
    meta:
        description = "Clipboard hijacker (crypto address swapping)"
        severity = "high"
        category = "infostealer"
    strings:
        $get = "GetClipboardData" nocase
        $set = "SetClipboardData" nocase
        $open = "OpenClipboard" nocase
        $btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        $eth = /0x[a-fA-F0-9]{40}/
    condition:
        ($get and $set and $open) and ($btc or $eth)
}

rule HawkScan_Credential_Store_Theft
{
    meta:
        description = "Theft of stored application credentials"
        severity = "high"
        category = "credential-access"
    strings:
        $a = "Software\\SimonTatham\\PuTTY\\Sessions" nocase
        $b = "WinSCP.ini" nocase
        $c = "recentservers.xml" nocase    // FileZilla
        $d = "sitemanager.xml" nocase
        $e = "Software\\Martin Prikryl" nocase
        $f = "logins.json" nocase           // Firefox
    condition:
        2 of them
}

rule HawkScan_ScheduledTask_Persistence
{
    meta:
        description = "Scheduled-task persistence creation"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "schtasks" nocase
        $b = "/create" nocase
        $c = "ITaskService" nocase
        $d = "TaskScheduler" nocase
        $e = "/sc onlogon" nocase
        $f = "/sc minute" nocase
    condition:
        ($a and $b) or ($c and $d) or ($a and ($e or $f))
}

rule HawkScan_Self_Deletion
{
    meta:
        description = "Self-deletion to remove the dropper after execution"
        severity = "medium"
        category = "defense-evasion"
    strings:
        $a = "cmd.exe /c del" nocase
        $b = "ping -n" nocase
        $c = "choice /C Y /N /D Y" nocase
        $d = "timeout /t" nocase
        $del = "del " nocase
    condition:
        ($a and ($b or $d)) or ($b and $del) or ($c and $del)
}

rule HawkScan_Generic_RAT
{
    meta:
        description = "Generic remote-access trojan capability combination"
        severity = "high"
        category = "rat"
    strings:
        $cap1 = "GetAsyncKeyState" nocase
        $cap2 = "BitBlt" nocase
        $cap3 = "GetClipboardData" nocase
        $net1 = "WSAStartup" nocase
        $net2 = "InternetOpen" nocase
        $net3 = "Net.WebClient" nocase
        $persist = "CurrentVersion\\Run" nocase
    condition:
        2 of ($cap*) and any of ($net*) and $persist
}

rule HawkScan_Process_Doppelganging
{
    meta:
        description = "Process doppelganging / ghosting via NTFS transactions"
        severity = "high"
        category = "process-injection"
    strings:
        $a = "CreateTransaction" nocase
        $b = "CreateFileTransactedW" nocase
        $c = "RollbackTransaction" nocase
        $d = "NtCreateProcessEx" nocase
        $e = "NtCreateSection" nocase
    condition:
        ($a and ($b or $c)) and ($d or $e)
}
