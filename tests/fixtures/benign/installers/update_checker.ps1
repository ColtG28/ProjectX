Write-Host "Checking for updates"
$versionUrl = "https://updates.example.local/version.json"
$destination = "$env:TEMP\\projectx_version.json"
powershell -NoProfile -Command {
    Invoke-WebRequest -Uri $using:versionUrl -OutFile $using:destination
}
if (Test-Path $destination) {
    Write-Host "Update manifest downloaded"
}
