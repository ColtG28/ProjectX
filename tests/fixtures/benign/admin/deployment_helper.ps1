Write-Host "Preparing deployment package"
$artifactRoot = "C:\\Deploy\\Release"
$packages = Get-ChildItem $artifactRoot -Filter "*.zip"
foreach ($package in $packages) {
    Write-Host ("Verifying " + $package.Name)
}
Start-BitsTransfer -Source "https://intranet.example.local/releases/manifest.json" -Destination "$env:TEMP\\manifest.json"
Invoke-Command -ComputerName localhost -ScriptBlock {
    Get-Date | Out-String
}
