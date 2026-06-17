/*
 * HawkScan built-in starter rules.
 * These are intentionally conservative, high-signal heuristics — not a
 * substitute for a maintained ruleset. Drop additional .yar files in this
 * directory (or point --rules at your own) to extend coverage.
 */

rule HawkScan_EICAR_Test
{
    meta:
        description = "EICAR antivirus test string (not real malware)"
        severity = "critical"
        category = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule HawkScan_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell launched with a hidden window and an encoded command"
        severity = "high"
        category = "execution"
    strings:
        $ps = "powershell" nocase
        $enc = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $hidden = "hidden" nocase
    condition:
        $ps and ($enc or $enc2) and $hidden
}

rule HawkScan_Suspicious_Download_Exec
{
    meta:
        description = "Download-and-execute cradle (IEX + web download)"
        severity = "high"
        category = "execution"
    strings:
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "Invoke-WebRequest" nocase
        $dl3 = "Net.WebClient" nocase
    condition:
        ($iex or $iex2) and ($dl1 or $dl2 or $dl3)
}

rule HawkScan_Ransom_ShadowCopy_Deletion
{
    meta:
        description = "Shadow-copy / backup deletion (common ransomware behavior)"
        severity = "high"
        category = "ransomware"
    strings:
        $v = "vssadmin" nocase
        $d = "delete shadows" nocase
        $w = "wbadmin" nocase
        $wd = "delete catalog" nocase
        $b = "bcdedit" nocase
        $br = "recoveryenabled no" nocase
    condition:
        ($v and $d) or ($w and $wd) or ($b and $br)
}

rule HawkScan_Embedded_PE_In_NonPE
{
    meta:
        description = "Embedded PE executable found inside a non-executable carrier"
        severity = "medium"
        category = "dropper"
    strings:
        $mz = "This program cannot be run in DOS mode"
    condition:
        // Carrier is not itself a PE (does not start with MZ) but contains a PE stub.
        not (uint16(0) == 0x5A4D) and $mz
}
