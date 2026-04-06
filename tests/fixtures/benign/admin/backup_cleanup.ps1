Write-Host "Running nightly cleanup"
$target = "C:\\Backups\\Daily"
Get-ChildItem $target -Recurse -File |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -WhatIf
Compress-Archive -Path "C:\\Logs\\*" -DestinationPath "$env:TEMP\\logs.zip"
Write-Host "Cleanup completed"
