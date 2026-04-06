Write-Host "Collecting environment details"
$os = Get-CimInstance Win32_OperatingSystem
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnet) {
    Write-Host "dotnet detected"
}
Invoke-WebRequest -Uri "https://updates.example.local/compatibility.json" -OutFile "$env:TEMP\\compatibility.json"
Write-Host $os.Caption
