rule suspicious_powershell_encoded_downloader {
    meta:
        confidence = "high"
        family = "powershell_downloader"
    strings:
        $a = "-EncodedCommand"
        $b = "FromBase64String"
        $c = "DownloadString"
    condition:
        all of them
}

rule suspicious_javascript_wsh_downloader {
    meta:
        confidence = "high"
        family = "javascript_launcher"
    strings:
        $a = "WScript.Shell"
        $b = "MSXML2.XMLHTTP"
        $c = "ADODB.Stream"
    condition:
        all of them
}

rule suspicious_office_macro_downloader {
    meta:
        confidence = "high"
        family = "office_download_chain"
    strings:
        $a = "AutoOpen"
        $b = "URLDownloadToFile"
        $c = "CreateObject"
    condition:
        all of them
}

rule suspicious_pe_injection_combo {
    meta:
        confidence = "high"
        family = "pe_injection"
    strings:
        $a = "VirtualAlloc"
        $b = "CreateRemoteThread"
    condition:
        all of them
}

rule suspicious_elf_shell_downloader {
    meta:
        confidence = "high"
        family = "elf_shell_downloader"
    strings:
        $a = "/bin/sh"
        $b = "curl "
    condition:
        all of them
}

rule suspicious_powershell_hidden_launcher {
    meta:
        confidence = "high"
        family = "powershell_launcher"
    strings:
        $a = "Invoke-WebRequest"
        $b = "Start-Process"
        $c = "WindowStyle Hidden"
    condition:
        all of them
}

rule suspicious_javascript_obfuscated_launcher {
    meta:
        confidence = "high"
        family = "javascript_launcher"
    strings:
        $a = "String.fromCharCode"
        $b = "ActiveXObject"
        $c = "WScript.Shell"
    condition:
        all of them
}

rule suspicious_office_autorun_network_chain {
    meta:
        confidence = "high"
        family = "office_network_chain"
    strings:
        $a = "Document_Open"
        $b = "MSXML2.XMLHTTP"
        $c = "ADODB.Stream"
    condition:
        all of them
}

rule suspicious_pe_scripted_follow_on {
    meta:
        confidence = "medium"
        family = "pe_scripted_follow_on"
    strings:
        $a = "powershell"
        $b = "-enc"
        $c = "DownloadString"
    condition:
        all of them
}

rule suspicious_elf_shell_network_chain {
    meta:
        confidence = "high"
        family = "elf_network_chain"
    strings:
        $a = "/bin/sh"
        $b = "socket"
        $c = "connect"
    condition:
        all of them
}

rule suspicious_powershell_bitsadmin_stager {
    meta:
        confidence = "medium"
        family = "powershell_stager"
    strings:
        $a = "bitsadmin"
        $b = "Start-BitsTransfer"
        $c = "Start-Process"
    condition:
        2 of them
}

rule suspicious_javascript_fetch_launcher {
    meta:
        confidence = "medium"
        family = "javascript_downloader"
    strings:
        $a = "fetch("
        $b = "atob("
        $c = "eval("
    condition:
        all of them
}

rule suspicious_office_shell_download_combo {
    meta:
        confidence = "high"
        family = "office_launcher"
    strings:
        $a = "Shell"
        $b = "URLDownloadToFile"
        $c = "Document_Open"
    condition:
        all of them
}

rule suspicious_encoded_stager_config {
    meta:
        confidence = "low"
        family = "encoded_stager"
    strings:
        $a = "FromBase64String"
        $b = "WriteAllBytes"
        $c = "stage"
    condition:
        all of them
}

rule suspicious_macho_loader_follow_on {
    meta:
        confidence = "medium"
        family = "macho_loader"
    strings:
        $a = "@loader_path"
        $b = "dlopen"
        $c = "dlsym"
    condition:
        all of them
}

rule suspicious_powershell_webclient_launcher {
    meta:
        confidence = "high"
        family = "powershell_webclient"
    strings:
        $a = "Net.WebClient"
        $b = "DownloadFile"
        $c = "Start-Process"
    condition:
        all of them
}

rule suspicious_javascript_blob_launcher {
    meta:
        confidence = "medium"
        family = "javascript_blob_launcher"
    strings:
        $a = "Blob("
        $b = "URL.createObjectURL"
        $c = "window.location"
    condition:
        all of them
}

rule suspicious_office_powershell_stager {
    meta:
        confidence = "high"
        family = "office_powershell_stager"
    strings:
        $a = "CreateObject(\"WScript.Shell\")"
        $b = "powershell"
        $c = "Document_Open"
    condition:
        all of them
}

rule suspicious_pe_loader_plus_powershell {
    meta:
        confidence = "medium"
        family = "pe_loader_follow_on"
    strings:
        $a = "LoadLibrary"
        $b = "GetProcAddress"
        $c = "powershell"
    condition:
        all of them
}

rule suspicious_elf_loader_network_symbols {
    meta:
        confidence = "medium"
        family = "elf_loader_network"
    strings:
        $a = "dlopen"
        $b = "dlsym"
        $c = "connect"
    condition:
        all of them
}

rule suspicious_macho_relative_loader_exec {
    meta:
        confidence = "medium"
        family = "macho_relative_loader_exec"
    strings:
        $a = "@loader_path"
        $b = "posix_spawn"
        $c = "dlopen"
    condition:
        all of them
}

rule suspicious_powershell_hidden_webrequest_chain {
    meta:
        confidence = "high"
        family = "powershell_hidden_webrequest"
    strings:
        $a = "Invoke-WebRequest"
        $b = "WindowStyle Hidden"
        $c = "Start-Process"
        $d = "UseBasicParsing"
    condition:
        3 of them
}

rule suspicious_javascript_fetch_blob_eval_chain {
    meta:
        confidence = "medium"
        family = "javascript_fetch_blob_eval"
    strings:
        $a = "fetch("
        $b = "Blob("
        $c = "URL.createObjectURL"
        $d = "eval("
    condition:
        3 of them
}

rule suspicious_office_template_shell_stager {
    meta:
        confidence = "medium"
        family = "office_template_stager"
    strings:
        $a = "AutoOpen"
        $b = "CreateObject(\"WScript.Shell\")"
        $c = "Shell"
        $d = "URLDownloadToFile"
    condition:
        3 of them
}

rule suspicious_package_stager_config {
    meta:
        confidence = "low"
        family = "config_stager"
    strings:
        $a = "config"
        $b = "stage"
        $c = "payload"
        $d = "FromBase64String"
    condition:
        3 of them
}

rule suspicious_pe_loader_network_follow_on {
    meta:
        confidence = "medium"
        family = "pe_loader_network"
    strings:
        $a = "LoadLibrary"
        $b = "GetProcAddress"
        $c = "WinHttpOpen"
        $d = "URLDownloadToFile"
    condition:
        3 of them
}

rule suspicious_elf_exec_network_loader {
    meta:
        confidence = "medium"
        family = "elf_exec_network_loader"
    strings:
        $a = "execve"
        $b = "socket"
        $c = "connect"
        $d = "dlopen"
    condition:
        3 of them
}

rule suspicious_macho_loader_network_path {
    meta:
        confidence = "medium"
        family = "macho_loader_network_path"
    strings:
        $a = "@loader_path"
        $b = "dlopen"
        $c = "NSURLSession"
        $d = "posix_spawn"
    condition:
        3 of them
}

rule suspicious_powershell_hidden_archive_launcher {
    meta:
        confidence = "medium"
        family = "powershell_hidden_archive_launcher"
    strings:
        $a = "Start-BitsTransfer"
        $b = "Expand-Archive"
        $c = "Start-Process"
        $d = "-WindowStyle Hidden"
    condition:
        3 of them
}

rule suspicious_cross_platform_loader_config_stage {
    meta:
        confidence = "medium"
        family = "cross_platform_loader_config"
    strings:
        $a = "LoadLibrary"
        $b = "dlopen"
        $c = "@loader_path"
        $d = "payload"
        $e = "config"
    condition:
        3 of them
}

rule suspicious_office_encoded_shell_stage {
    meta:
        confidence = "medium"
        family = "office_encoded_shell_stage"
    strings:
        $a = "Document_Open"
        $b = "WScript.Shell"
        $c = "FromBase64String"
        $d = "Shell"
    condition:
        3 of them
}

rule suspicious_macho_relative_loader_spawn_network {
    meta:
        confidence = "medium"
        family = "macho_relative_loader_spawn_network"
    strings:
        $a = "@loader_path"
        $b = "dlopen"
        $c = "posix_spawn"
        $d = "NSURLSession"
    condition:
        3 of them
}

rule suspicious_powershell_archive_download_launcher {
    meta:
        confidence = "high"
        family = "powershell_archive_launcher"
    strings:
        $a = "Invoke-WebRequest"
        $b = "Expand-Archive"
        $c = "Start-Process"
        $d = ".zip"
    condition:
        3 of them
}

rule suspicious_javascript_fetch_decode_blob_chain {
    meta:
        confidence = "medium"
        family = "javascript_fetch_decode_blob"
    strings:
        $a = "fetch("
        $b = "atob("
        $c = "Blob("
        $d = "URL.createObjectURL"
    condition:
        3 of them
}

rule suspicious_archive_extract_execute_chain {
    meta:
        confidence = "medium"
        family = "archive_extract_execute"
    strings:
        $a = "Expand-Archive"
        $b = "ExtractToDirectory"
        $c = "Start-Process"
        $d = ".zip"
    condition:
        3 of them
}

rule suspicious_pe_injection_network_chain {
    meta:
        confidence = "high"
        family = "pe_injection_network"
    strings:
        $a = "VirtualAlloc"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "WinHttpOpen"
    condition:
        3 of them
}

rule suspicious_cross_platform_script_chain {
    meta:
        confidence = "high"
        family = "cross_platform_script_chain"
        rationale = "Requires downloader, decode, and launcher-style script markers across platforms"
    strings:
        $a = "Invoke-WebRequest"
        $b = "curl "
        $c = "FromBase64String"
        $d = "Start-Process"
        $e = "sh -c"
    condition:
        4 of them
}

rule suspicious_archive_nested_execution_chain {
    meta:
        confidence = "high"
        family = "archive_nested_execution_chain"
        rationale = "Requires archive extraction plus follow-on execution markers"
    strings:
        $a = "Expand-Archive"
        $b = "ExtractToDirectory"
        $c = "Start-Process"
        $d = "chmod +x"
        $e = ".zip"
    condition:
        4 of them
}

rule suspicious_encoded_config_loader_chain {
    meta:
        confidence = "medium"
        family = "encoded_config_loader_chain"
        rationale = "Requires encoded config plus loader/stager markers"
    strings:
        $a = "FromBase64String"
        $b = "config"
        $c = "payload"
        $d = "LoadLibrary"
        $e = "dlopen"
    condition:
        4 of them
}

rule suspicious_multi_stage_download_pattern {
    meta:
        confidence = "high"
        family = "multi_stage_download_pattern"
        rationale = "Requires multi-stage download, staging, and execution-style markers"
    strings:
        $a = "DownloadFile"
        $b = "Invoke-WebRequest"
        $c = "stage"
        $d = "Start-Process"
        $e = "WriteAllBytes"
    condition:
        4 of them
}

rule suspicious_installer_script_spawn_chain {
    meta:
        confidence = "medium"
        family = "installer_script_spawn_chain"
        rationale = "Requires installer/update context plus script-spawn and network markers"
    strings:
        $a = "msiexec"
        $b = "powershell"
        $c = "Start-Process"
        $d = "DownloadString"
        $e = "update"
    condition:
        4 of them
}
