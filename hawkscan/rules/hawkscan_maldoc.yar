/*
 * HawkScan malicious-document rules (original).
 * Generic detections for weaponised Office/document content: macro download
 * cradles, Excel 4.0 (XLM) macros, DDE execution, remote template injection,
 * and PowerShell embedded in documents.
 */

rule HawkScan_Maldoc_Macro_Cradle
{
    meta:
        description = "VBA macro download-and-execute cradle"
        severity = "high"
        category = "maldoc"
    strings:
        $net1 = "MSXML2.XMLHTTP" nocase
        $net2 = "WinHttp.WinHttpRequest" nocase
        $net3 = "URLDownloadToFile" nocase
        $run1 = "WScript.Shell" nocase
        $run2 = "Shell(" nocase
        $run3 = "CreateObject" nocase
        $save = "ADODB.Stream" nocase
    condition:
        any of ($net*) and (any of ($run*) or $save)
}

rule HawkScan_Maldoc_Excel4_Macro
{
    meta:
        description = "Excel 4.0 (XLM) macro execution primitives"
        severity = "high"
        category = "maldoc"
    strings:
        $a = "Auto_Open" nocase
        $b = "=EXEC(" nocase
        $c = "=CALL(" nocase
        $d = "=REGISTER(" nocase
        $e = "URLMon" nocase
    condition:
        ($a and any of ($b,$c,$d)) or ($d and $e)
}

rule HawkScan_Maldoc_DDE
{
    meta:
        description = "DDE/DDEAUTO command execution in document"
        severity = "high"
        category = "maldoc"
    strings:
        $a = "DDEAUTO" nocase
        $b = "DDE " nocase
        $c = "cmd.exe" nocase
        $d = "powershell" nocase
        $e = "\\\\..\\\\"
    condition:
        (($a or $b) and ($c or $d)) or ($a and $e)
}

rule HawkScan_Maldoc_Remote_Template
{
    meta:
        description = "Remote template injection (OOXML relationship to remote .dotm)"
        severity = "high"
        category = "maldoc"
    strings:
        $a = "attachedTemplate" nocase
        $b = "TargetMode=\"External\"" nocase
        $c = "http" nocase
        $d = "Target=\"http" nocase
    condition:
        ($a and $b and $c) or $d
}

rule HawkScan_Maldoc_Embedded_PowerShell
{
    meta:
        description = "PowerShell payload embedded in a document"
        severity = "high"
        category = "maldoc"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
        $d = "FromBase64String" nocase
        $e = "IEX" nocase
        $f = "DownloadString" nocase
    condition:
        $a and 2 of ($b,$c,$d,$e,$f)
}
