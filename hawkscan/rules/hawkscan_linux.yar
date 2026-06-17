/*
 * HawkScan Linux/ELF rules (original).
 * Generic detections for Linux malware behaviours: shell droppers, persistence,
 * userland rootkits, botnet/miner traits, and credential/SSH theft. Conservative
 * multi-string conditions to limit false positives on benign system tooling.
 */

rule HawkScan_Linux_Download_Pipe_Shell
{
    meta:
        description = "Download-and-pipe-to-shell dropper cradle"
        severity = "high"
        category = "execution"
    strings:
        $w = "wget" nocase
        $c = "curl" nocase
        $sh1 = "| sh" nocase
        $sh2 = "|sh" nocase
        $sh3 = "| bash" nocase
        $sh4 = "bash -c" nocase
        $b64 = "base64 -d" nocase
    condition:
        (($w or $c) and any of ($sh1,$sh2,$sh3)) or ($b64 and $sh4)
}

rule HawkScan_Linux_Persistence
{
    meta:
        description = "Linux persistence via cron/rc/systemd/profile"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "/etc/cron." nocase
        $b = "crontab -" nocase
        $c = "/etc/rc.local" nocase
        $d = "/etc/init.d/" nocase
        $e = ".bashrc" nocase
        $f = "/etc/systemd/system/" nocase
        $g = "/etc/profile.d/" nocase
    condition:
        2 of them
}

rule HawkScan_Linux_Userland_Rootkit
{
    meta:
        description = "LD_PRELOAD userland rootkit / library hijack"
        severity = "high"
        category = "rootkit"
    strings:
        $a = "LD_PRELOAD" nocase
        $b = "/etc/ld.so.preload" nocase
        $c = "dlsym" nocase
        $d = "readdir" nocase
        $e = "RTLD_NEXT" nocase
    condition:
        ($a and ($c or $e)) or $b
}

rule HawkScan_Linux_SSH_Theft
{
    meta:
        description = "SSH key / authorized_keys targeting"
        severity = "high"
        category = "credential-access"
    strings:
        $a = ".ssh/authorized_keys" nocase
        $b = ".ssh/id_rsa" nocase
        $c = "known_hosts" nocase
        $d = "ssh-rsa AAAA"
    condition:
        2 of them
}

rule HawkScan_Linux_Botnet_Traits
{
    meta:
        description = "Generic Linux IoT botnet traits (Mirai-like)"
        severity = "high"
        category = "botnet"
    strings:
        $a = "/bin/busybox" nocase
        $b = "TSource Engine Query"
        $c = "/proc/net/tcp" nocase
        $d = "watchdog" nocase
        $e = "/dev/watchdog" nocase
        $f = "kill -9" nocase
    condition:
        ($a and ($c or $e)) or ($b and $f) or 3 of them
}

rule HawkScan_Linux_AntiForensics
{
    meta:
        description = "Anti-forensics: log/history tampering"
        severity = "medium"
        category = "defense-evasion"
    strings:
        $a = "/var/log/wtmp" nocase
        $b = "/var/log/secure" nocase
        $c = "history -c" nocase
        $d = "HISTFILE" nocase
        $e = "shred " nocase
        $f = "unset HISTFILE" nocase
    condition:
        2 of them
}
