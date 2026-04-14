param(
    [string]$OutDir = "release-artifacts/windows"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$AppName = "ProjectX"
$BinaryPath = Join-Path $RootDir "target/release/$AppName.exe"

if (-not (Test-Path $BinaryPath)) {
    throw "Missing release binary at $BinaryPath. Run 'cargo build --release --locked' first."
}

$PackageDir = Join-Path $RootDir $OutDir
$PortableDir = Join-Path $PackageDir "$AppName-portable"
$ZipPath = Join-Path $PackageDir "$AppName-windows.zip"
$ShaPath = "$ZipPath.sha256"

if (Test-Path $PortableDir) { Remove-Item -Recurse -Force $PortableDir }
New-Item -ItemType Directory -Force -Path $PortableDir | Out-Null

Copy-Item $BinaryPath (Join-Path $PortableDir "$AppName.exe")
Copy-Item (Join-Path $RootDir "README.md") $PortableDir
Copy-Item (Join-Path $RootDir "LICENSE") $PortableDir

if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path (Join-Path $PortableDir "*") -DestinationPath $ZipPath -Force
$Hash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLower()
Set-Content -Path $ShaPath -Value "$Hash  $(Split-Path -Leaf $ZipPath)"

Write-Host "Created Windows portable release: $ZipPath"
