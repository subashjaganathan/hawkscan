/*
 * HawkScan mobile rules (original).
 * Generic detections for Android and iOS threats: banking-trojan overlays,
 * accessibility abuse, jailbreak/root checks, and iOS private-API / profile
 * abuse. Conservative multi-string conditions.
 */

rule HawkScan_Android_Banking_Overlay
{
    meta:
        description = "Android banking trojan: overlay + accessibility abuse"
        severity = "high"
        category = "banker"
    strings:
        $a = "TYPE_ACCESSIBILITY_OVERLAY" nocase
        $b = "SYSTEM_ALERT_WINDOW" nocase
        $c = "BIND_ACCESSIBILITY_SERVICE" nocase
        $d = "onAccessibilityEvent" nocase
        $e = "addView" nocase
    condition:
        ($b and ($c or $d)) or ($a and $e)
}

rule HawkScan_Android_RAT
{
    meta:
        description = "Android RAT: SMS interception + C2 command handling"
        severity = "high"
        category = "rat"
    strings:
        $a = "abortBroadcast" nocase
        $b = "SmsReceiver" nocase
        $c = "getRunningServices" nocase
        $d = "Camera.open" nocase
        $e = "MediaRecorder" nocase
        $f = "DeviceAdminReceiver" nocase
    condition:
        3 of them
}

rule HawkScan_iOS_Jailbreak_Or_PrivateAPI
{
    meta:
        description = "iOS app referencing jailbreak paths or private APIs"
        severity = "medium"
        category = "ios"
    strings:
        $jb1 = "/Applications/Cydia.app" nocase
        $jb2 = "/bin/bash"
        $jb3 = "/usr/sbin/sshd"
        $jb4 = "MobileSubstrate" nocase
        $api1 = "_dyld_get_image_name"
        $api2 = "task_for_pid"
    condition:
        2 of ($jb*) or (any of ($api1,$api2) and any of ($jb*))
}

rule HawkScan_iOS_Config_Profile_Abuse
{
    meta:
        description = "iOS configuration-profile / MDM abuse indicators"
        severity = "medium"
        category = "ios"
    strings:
        $a = "PayloadType" nocase
        $b = "com.apple.mdm" nocase
        $c = "PayloadRemovalDisallowed" nocase
        $d = "com.apple.webClip.managed" nocase
    condition:
        ($a and ($b or $c)) or $d
}
