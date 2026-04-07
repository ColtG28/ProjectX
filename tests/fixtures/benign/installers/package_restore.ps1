$cacheRoot = "$env:TEMP\\projectx-package-cache"
$packageName = "safe-tooling"
$manifest = Join-Path $cacheRoot "package-lock.json"

Write-Host "Restoring cached package metadata for installer validation"
Write-Host "Reading package manifest and lock data"
Write-Host "No hidden windows, encoded payloads, or launch steps"
if (Test-Path $manifest) { Get-Content $manifest | Out-Null }
