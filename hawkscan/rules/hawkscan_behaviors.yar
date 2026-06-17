/*
 * HawkScan behavioural rules (original).
 * Conservative, high-signal detections for common malware behaviours. These
 * complement the bundled starter rules and the optional YARA-Forge community
 * set; they are intentionally generic so they generalise across families.
 */

rule HawkScan_Webshell_PHP_Eval
{
    meta:
        description = "PHP webshell: dynamic execution of request input"
        severity = "high"
        category = "webshell"
    strings:
        $php = "<?php"
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $sys = "system(" nocase
        $passthru = "passthru(" nocase
        $shell = "shell_exec(" nocase
        $req1 = "$_POST"
        $req2 = "$_GET"
        $req3 = "$_REQUEST"
    condition:
        $php and any of ($eval,$assert,$sys,$passthru,$shell)
        and any of ($req1,$req2,$req3)
}

rule HawkScan_Webshell_ChinaChopper
{
    meta:
        description = "China Chopper style one-line webshell"
        severity = "high"
        category = "webshell"
    strings:
        $a = /<%@\s*Page\s+Language=.Jscript/ nocase
        $b = "eval(Request.Item[" nocase
        $c = /<\?php.{0,20}@eval\(\$_(POST|GET|REQUEST)/ nocase
    condition:
        any of them
}

rule HawkScan_Ransom_Note
{
    meta:
        description = "Generic ransomware ransom-note language"
        severity = "high"
        category = "ransomware"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files" nocase
        $c = "to decrypt" nocase
        $d = "bitcoin" nocase
        $e = "private key" nocase
        $f = ".onion" nocase
    condition:
        $a or ($c and $d) or ($b and ($d or $f) and $e)
}

rule HawkScan_Mimikatz
{
    meta:
        description = "Mimikatz credential-theft tool artefacts"
        severity = "critical"
        category = "credential-access"
    strings:
        $a = "sekurlsa" nocase
        $b = "gentilkiwi" nocase
        $c = "mimikatz" nocase
        $d = "logonpasswords" nocase
        $e = "kerberos::" nocase
    condition:
        2 of them
}

rule HawkScan_LOLBin_Abuse
{
    meta:
        description = "Living-off-the-land binary abuse (download/decode)"
        severity = "medium"
        category = "execution"
    strings:
        $a = "certutil" nocase
        $a2 = "-decode" nocase
        $a3 = "-urlcache" nocase
        $b = "bitsadmin" nocase
        $b2 = "/transfer" nocase
        $c = "regsvr32" nocase
        $c2 = "scrobj.dll" nocase
        $d = "mshta" nocase
        $d2 = "javascript:" nocase
    condition:
        ($a and ($a2 or $a3)) or ($b and $b2) or ($c and $c2) or ($d and $d2)
}

rule HawkScan_CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon indicators"
        severity = "critical"
        category = "c2"
    strings:
        $a = "ReflectiveLoader"
        $b = "%s as %s\\%s: %d"
        $c = "beacon.dll" nocase
        $d = "%02d/%02d/%02d %02d:%02d:%02d"
        $e = "Could not connect to pipe"
    condition:
        $a and 1 of ($b,$c,$d,$e)
}

rule HawkScan_Suspicious_VBA_AutoExec
{
    meta:
        description = "Office VBA macro auto-exec combined with shell/download"
        severity = "high"
        category = "macro"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $sh1 = "Shell" nocase
        $sh2 = "CreateObject" nocase
        $sh3 = "WScript.Shell" nocase
        $sh4 = "powershell" nocase
    condition:
        any of ($auto*) and any of ($sh*)
}
