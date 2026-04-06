rule suspicious_powershell_encoded_downloader {
    strings:
        $a = "-EncodedCommand"
        $b = "FromBase64String"
        $c = "DownloadString"
    condition:
        all of them
}

rule suspicious_javascript_wsh_downloader {
    strings:
        $a = "WScript.Shell"
        $b = "MSXML2.XMLHTTP"
        $c = "ADODB.Stream"
    condition:
        all of them
}

rule suspicious_office_macro_downloader {
    strings:
        $a = "AutoOpen"
        $b = "URLDownloadToFile"
        $c = "CreateObject"
    condition:
        all of them
}

rule suspicious_pe_injection_combo {
    strings:
        $a = "VirtualAlloc"
        $b = "CreateRemoteThread"
    condition:
        all of them
}

rule suspicious_elf_shell_downloader {
    strings:
        $a = "/bin/sh"
        $b = "curl "
    condition:
        all of them
}

rule suspicious_powershell_hidden_launcher {
    strings:
        $a = "Invoke-WebRequest"
        $b = "Start-Process"
        $c = "WindowStyle Hidden"
    condition:
        all of them
}

rule suspicious_javascript_obfuscated_launcher {
    strings:
        $a = "String.fromCharCode"
        $b = "ActiveXObject"
        $c = "WScript.Shell"
    condition:
        all of them
}

rule suspicious_office_autorun_network_chain {
    strings:
        $a = "Document_Open"
        $b = "MSXML2.XMLHTTP"
        $c = "ADODB.Stream"
    condition:
        all of them
}

rule suspicious_pe_scripted_follow_on {
    strings:
        $a = "powershell"
        $b = "-enc"
        $c = "DownloadString"
    condition:
        all of them
}

rule suspicious_elf_shell_network_chain {
    strings:
        $a = "/bin/sh"
        $b = "socket"
        $c = "connect"
    condition:
        all of them
}
