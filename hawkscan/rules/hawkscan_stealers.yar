/*
 * HawkScan stealer / loader / RAT rules (original).
 * Conservative, high-signal detections for prevalent commodity threats.
 * Conditions require multiple corroborating indicators to keep false
 * positives low; family-name words that collide with legitimate software
 * (e.g. "Quasar") are avoided in favour of distinctive internal markers.
 */

rule HawkScan_Infostealer_BrowserCredentialTheft
{
    meta:
        description = "Infostealer harvesting browser credentials + wallets/exfil"
        severity = "high"
        category = "infostealer"
    strings:
        $b1 = "\\Google\\Chrome\\User Data" nocase
        $b2 = "\\Microsoft\\Edge\\User Data" nocase
        $b3 = "\\BraveSoftware\\Brave-Browser\\User Data" nocase
        $b4 = "Login Data"
        $b5 = "Local State"
        $b6 = "cookies.sqlite" nocase
        $b7 = "moz_cookies"
        $w1 = "wallet.dat" nocase
        $w2 = "\\Electrum\\wallets" nocase
        $w3 = "\\Exodus\\exodus.wallet" nocase
        $w4 = "\\Ethereum\\keystore" nocase
        $x1 = "api.telegram.org/bot" nocase
        $x2 = "/sendDocument" nocase
        $x3 = "discord.com/api/webhooks" nocase
    condition:
        2 of ($b*) and (any of ($w*) or any of ($x*))
}

rule HawkScan_Clipboard_CryptoClipper
{
    meta:
        description = "Clipboard crypto-clipper: swaps copied wallet addresses"
        severity = "high"
        category = "cryptostealer"
    strings:
        $open = "OpenClipboard"
        $get = "GetClipboardData"
        $set = "SetClipboardData"
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $eth = /0x[0-9a-fA-F]{40}/
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
    condition:
        $open and $get and $set and 1 of ($btc, $eth, $xmr)
}

rule HawkScan_Shellcode_Loader_InjectionTriad
{
    meta:
        description = "In-memory shellcode loader: process-injection API triad"
        severity = "high"
        category = "loader"
    strings:
        $alloc1 = "VirtualAllocEx"
        $alloc2 = "NtAllocateVirtualMemory"
        $write = "WriteProcessMemory"
        $exec1 = "CreateRemoteThread"
        $exec2 = "QueueUserAPC"
        $exec3 = "NtUnmapViewOfSection"
        $exec4 = "SetThreadContext"
    condition:
        uint16(0) == 0x5A4D and $write and 1 of ($alloc*) and 1 of ($exec*)
}

rule HawkScan_CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Cobalt Strike beacon: default named pipes / reflective loader"
        severity = "high"
        category = "c2"
    strings:
        $p1 = "\\\\.\\pipe\\msagent_" nocase
        $p2 = "\\\\.\\pipe\\MSSE-" nocase
        $p3 = "\\\\.\\pipe\\status_" nocase
        $p4 = "\\\\.\\pipe\\postex_" nocase
        $b1 = "ReflectiveLoader"
        $b2 = "beacon.dll" nocase
        $b3 = "%s as %s\\%s: %d"
        $b4 = "could not spawn %s: %d"
    condition:
        any of ($p*) or ($b1 and $b2) or ($b3 and $b4)
}

rule HawkScan_Keylogger_LogFormat
{
    meta:
        description = "Keylogger: keystroke log markers + key-capture API"
        severity = "medium"
        category = "keylogger"
    strings:
        $k1 = "[ENTER]"
        $k2 = "[BACKSPACE]"
        $k3 = "[CTRL]"
        $k4 = "[TAB]"
        $k5 = "[ESC]"
        $k6 = "[Window:" nocase
        $k7 = "[Clipboard]" nocase
        $api1 = "GetAsyncKeyState"
        $api2 = "SetWindowsHookEx"
    condition:
        3 of ($k*) and 1 of ($api*)
}

rule HawkScan_DotNet_RAT_Markers
{
    meta:
        description = ".NET RAT distinctive internal markers (AsyncRAT/DcRat/Quasar)"
        severity = "high"
        category = "rat"
    strings:
        $a1 = "AsyncClient" nocase
        $a2 = "GetKeyloggerLogsResponse"
        $a3 = "DoUploadAndExecute"
        $a4 = "DoProcessKill"
        $a5 = "Server Certificate"
        $a6 = "Pastebin" nocase
        $a7 = "ClientInstaller" nocase
        $a8 = "RemoteDesktop" nocase
    condition:
        2 of them
}
