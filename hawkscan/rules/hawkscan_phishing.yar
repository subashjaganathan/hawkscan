/*
 * HawkScan HTML / phishing rules (original).
 * Generic detections for phishing kits, HTML smuggling, and web-delivered
 * droppers. Conservative multi-string conditions to limit false positives on
 * legitimate web pages.
 */

rule HawkScan_HTML_Smuggling
{
    meta:
        description = "HTML smuggling: in-page blob built and auto-downloaded"
        severity = "high"
        category = "html-smuggling"
    strings:
        $b64 = "atob(" nocase
        $blob = "new Blob(" nocase
        $url = "createObjectURL" nocase
        $dl1 = "download=" nocase
        $dl2 = ".click()" nocase
        $a = "msSaveOrOpenBlob" nocase
    condition:
        ($b64 and $blob and ($url or $a)) and ($dl1 or $dl2)
}

rule HawkScan_Phishing_Credential_Form
{
    meta:
        description = "Credential-harvesting form posting off-site"
        severity = "medium"
        category = "phishing"
    strings:
        $pw = "type=\"password\"" nocase
        $form = "<form" nocase
        $post = "method=\"post\"" nocase
        $ext1 = "action=\"http" nocase
        $send = "mail(" nocase
        $tg = "api.telegram.org/bot" nocase
    condition:
        $pw and $form and ($post and ($ext1 or $send or $tg))
}

rule HawkScan_HTML_Eval_Dropper
{
    meta:
        description = "Obfuscated in-page script dropper (eval/unescape)"
        severity = "high"
        category = "html-smuggling"
    strings:
        $e1 = "eval(" nocase
        $e2 = "Function(" nocase
        $u1 = "unescape(" nocase
        $u2 = "decodeURIComponent(" nocase
        $f1 = "fromCharCode" nocase
        $ws = "WScript.Shell" nocase
        $hta = "ActiveXObject" nocase
    condition:
        (any of ($e1,$e2) and any of ($u1,$u2,$f1)) or ($hta and $ws)
}

rule HawkScan_Webshell_ASPX_JSP
{
    meta:
        description = "ASP.NET / JSP webshell command execution"
        severity = "high"
        category = "webshell"
    strings:
        $asp1 = "Process.Start" nocase
        $asp2 = "System.Diagnostics" nocase
        $asp3 = "Request[" nocase
        $asp4 = "cmd.exe" nocase
        $jsp1 = "Runtime.getRuntime().exec" nocase
        $jsp2 = "request.getParameter" nocase
        $jsp3 = "<%@ page" nocase
    condition:
        ($asp1 and $asp3) or ($asp2 and $asp4 and $asp3)
        or ($jsp1 and $jsp2) or ($jsp1 and $jsp3)
}
