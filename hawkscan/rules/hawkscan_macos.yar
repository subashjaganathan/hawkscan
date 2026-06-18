/*
 * HawkScan macOS rules (original).
 * Generic detections for macOS malware behaviours: persistence via launch
 * agents/daemons, AppleScript abuse, Gatekeeper/quarantine tampering, TCC
 * privacy-bypass, and credential/keychain theft. Conservative multi-string
 * conditions to limit false positives on legitimate apps.
 */

rule HawkScan_macOS_LaunchPersistence
{
    meta:
        description = "Persistence via LaunchAgents/LaunchDaemons plist"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "LaunchAgents" nocase
        $b = "LaunchDaemons" nocase
        $c = "RunAtLoad" nocase
        $d = "KeepAlive" nocase
        $e = "/Library/LaunchAgents" nocase
    condition:
        (any of ($a,$b,$e)) and (any of ($c,$d))
}

rule HawkScan_macOS_AppleScript_Abuse
{
    meta:
        description = "AppleScript / osascript used for execution or prompts"
        severity = "medium"
        category = "execution"
    strings:
        $a = "osascript" nocase
        $b = "do shell script" nocase
        $c = "with administrator privileges" nocase
        $d = "display dialog" nocase
        $e = "NSAppleScript" nocase
    condition:
        ($a and ($b or $c)) or ($b and $c) or ($d and $c) or ($e and $b)
}

rule HawkScan_macOS_Gatekeeper_Tamper
{
    meta:
        description = "Gatekeeper / quarantine attribute tampering"
        severity = "high"
        category = "defense-evasion"
    strings:
        $a = "com.apple.quarantine" nocase
        $b = "xattr -d" nocase
        $c = "xattr -c" nocase
        $d = "spctl --master-disable" nocase
        $e = "spctl --add" nocase
    condition:
        ($a and ($b or $c)) or $d or $e
}

rule HawkScan_macOS_TCC_Bypass
{
    meta:
        description = "TCC privacy database access (camera/mic/screen bypass)"
        severity = "high"
        category = "privacy"
    strings:
        $a = "TCC.db" nocase
        $b = "com.apple.TCC" nocase
        $c = "kTCCService" nocase
        $d = "ScreenCapture" nocase
        $e = "AppleEvents" nocase
    condition:
        ($a or $b) and any of ($c,$d,$e)
}

rule HawkScan_macOS_Keychain_Theft
{
    meta:
        description = "Keychain / credential access on macOS"
        severity = "high"
        category = "credential-access"
    strings:
        $a = "security find-generic-password" nocase
        $b = "login.keychain" nocase
        $c = "SecKeychain" nocase
        $d = "dump-keychain" nocase
        $e = "/Library/Keychains" nocase
    condition:
        2 of them
}

rule HawkScan_macOS_Download_Exec
{
    meta:
        description = "Download-and-execute via curl/osascript on macOS"
        severity = "high"
        category = "execution"
    strings:
        $a = "curl" nocase
        $b = "-o /tmp/" nocase
        $c = "chmod +x" nocase
        $d = "| /bin/sh" nocase
        $e = "| bash" nocase
        $f = "/usr/bin/osascript" nocase
    condition:
        ($a and ($b or $d or $e)) or ($a and $c) or ($f and $c)
}

rule HawkScan_macOS_Stealer
{
    meta:
        description = "macOS infostealer combo (fake password prompt + exfil)"
        severity = "high"
        category = "infostealer"
    strings:
        $p1 = "display dialog" nocase
        $p2 = "password" nocase
        $p3 = "with hidden answer" nocase
        $k = "login.keychain" nocase
        $b = "Cookies.binarycookies" nocase
        $exf1 = "curl" nocase
        $w = "Library/Application Support" nocase
    condition:
        ($p1 and $p2 and $p3) or ($k and $exf1) or ($b and $w and $exf1)
}

rule HawkScan_macOS_Dylib_Hijack
{
    meta:
        description = "Dylib hijacking / insecure load path"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "DYLD_INSERT_LIBRARIES" nocase
        $b = "@rpath" nocase
        $c = "@executable_path" nocase
        $d = "LC_LOAD_WEAK_DYLIB" nocase
    condition:
        $a or ($d and ($b or $c))
}
