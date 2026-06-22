/*
 * HawkScan family/technique rules (original).
 * Generic, high-signal detections for common malware classes and techniques.
 * Written to generalise across families rather than pin a single sample, and
 * kept conservative (multi-string conditions) to limit false positives on
 * legitimate software.
 */

rule HawkScan_Infostealer_Browser
{
    meta:
        description = "Browser credential/cookie theft (infostealer)"
        severity = "high"
        category = "infostealer"
    strings:
        $a = "Login Data" nocase
        $b = "cookies.sqlite" nocase
        $c = "Local State" nocase
        $d = "\\Google\\Chrome\\User Data" nocase
        $e = "moz_cookies" nocase
        $f = "encrypted_key" nocase
    condition:
        3 of them
}

rule HawkScan_Crypto_Wallet_Theft
{
    meta:
        description = "Cryptocurrency wallet file targeting"
        severity = "high"
        category = "infostealer"
    strings:
        $a = "wallet.dat" nocase
        $b = "\\Electrum\\wallets" nocase
        $c = "\\Exodus\\exodus.wallet" nocase
        $d = "keystore" nocase
        $e = "MetaMask" nocase
    condition:
        2 of them
}

rule HawkScan_Discord_Token_Stealer
{
    meta:
        description = "Discord/Telegram token or webhook exfiltration"
        severity = "high"
        category = "infostealer"
    strings:
        $a = "discord.com/api/webhooks" nocase
        $b = "discordapp.com/api" nocase
        $c = "Local Storage\\leveldb" nocase
        $d = "api.telegram.org/bot" nocase
        $e = "/sendMessage" nocase
    condition:
        $a or $d or ($b and $c) or ($d and $e)
}

rule HawkScan_CryptoMiner
{
    meta:
        description = "Cryptocurrency miner (XMRig / stratum)"
        severity = "high"
        category = "miner"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "xmrig" nocase
        $c = "donate-level" nocase
        $d = "randomx" nocase
        $e = "cryptonight" nocase
    condition:
        $a or 2 of ($b,$c,$d,$e)
}

rule HawkScan_AntiVM
{
    meta:
        description = "Anti-VM / sandbox environment checks"
        severity = "medium"
        category = "anti-vm"
    strings:
        $a = "VMware" nocase
        $b = "VBOX" nocase
        $c = "VirtualBox" nocase
        $d = "QEMU" nocase
        $e = "vmtoolsd" nocase
        $f = "SbieDll.dll" nocase
        $g = "HARDWARE\\ACPI\\DSDT\\VBOX__" nocase
    condition:
        3 of them
}

rule HawkScan_UAC_Bypass
{
    meta:
        description = "Known UAC bypass technique markers"
        severity = "high"
        category = "privilege-escalation"
    strings:
        $a = "fodhelper.exe" nocase
        $b = "eventvwr.exe" nocase
        $c = "computerdefaults.exe" nocase
        $d = "ms-settings\\shell\\open\\command" nocase
        $e = "sdclt.exe" nocase
    condition:
        ($d and any of ($a,$b,$c,$e)) or 2 of ($a,$b,$c,$e)
}

rule HawkScan_Credential_Dump_LSASS
{
    meta:
        description = "LSASS memory dumping for credential theft"
        severity = "critical"
        category = "credential-access"
    strings:
        $a = "lsass" nocase
        $b = "comsvcs.dll" nocase
        $c = "MiniDump" nocase
        $d = "SeDebugPrivilege" nocase
    condition:
        ($a and ($b or $c)) or ($c and $d)
}

rule HawkScan_Persistence_Markers
{
    meta:
        description = "Common Windows persistence locations"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "CurrentVersion\\Run" nocase
        $b = "CurrentVersion\\RunOnce" nocase
        $c = "schtasks" nocase
        $d = "\\Start Menu\\Programs\\Startup" nocase
        $e = "Image File Execution Options" nocase
        $f = "CurrentVersion\\Winlogon" nocase
    condition:
        2 of them
}

rule HawkScan_Ransomware_Behavior
{
    meta:
        description = "Ransomware: recovery tampering + encryption markers"
        severity = "high"
        category = "ransomware"
    strings:
        $a = "vssadmin" nocase
        $b = "delete shadows" nocase
        $c = "wbadmin" nocase
        $d = "bcdedit" nocase
        $e = "recoveryenabled" nocase
        $f = ".locked" nocase
        $g = "README" nocase
        $h = "DECRYPT" nocase
    condition:
        (($a or $c) and $b) or ($d and $e) or ($f and $h) or ($g and $h and ($a or $f))
}

rule HawkScan_Meterpreter_Shellcode
{
    meta:
        description = "Metasploit/Meterpreter staged payload markers"
        severity = "critical"
        category = "c2"
    strings:
        $a = "metsrv.dll" nocase
        $b = "stdapi" nocase
        $c = "core_channel_open" nocase
        $d = "PassageInLoading" nocase
    condition:
        2 of them
}

rule HawkScan_Packer_Names
{
    meta:
        description = "Known packer/protector signatures"
        severity = "low"
        category = "packer"
    strings:
        $a = "UPX!"
        $b = ".themida" nocase
        $c = "VMProtect" nocase
        $d = "MPRESS1"
        $e = "ConfuserEx" nocase
        $f = ".aspack" nocase
        $g = "Enigma" nocase
    condition:
        any of them
}

rule HawkScan_Reverse_Shell
{
    meta:
        description = "Reverse shell command patterns"
        severity = "high"
        category = "c2"
    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
        $c = "nc -e" nocase
        $d = "socket.SOCK_STREAM" nocase
        $f = "powershell -nop -c" nocase
        $g = "/bin/sh -i" nocase
        $h = "TCPClient" nocase
        $i = "subprocess" nocase
    condition:
        // socket+subprocess alone is common in legitimate code; require an
        // actual shell-invocation string too.
        ($a and ($b or $g)) or $c or ($f and $h) or ($d and $i and ($b or $g))
}

rule HawkScan_Keylogger
{
    meta:
        description = "Keylogging behaviour markers"
        severity = "high"
        category = "spyware"
    strings:
        $a = "GetAsyncKeyState"
        $b = "SetWindowsHookEx"
        $c = "GetForegroundWindow"
        $d = "[ENTER]" nocase
        $e = "[BACKSPACE]" nocase
        $f = "keylog" nocase
    condition:
        // Capture APIs alone are common in GUI apps; require keystroke-log
        // formatting strings or the explicit "keylog" marker.
        $f or ($b and ($d or $e)) or ($a and $c and ($d or $e))
}
