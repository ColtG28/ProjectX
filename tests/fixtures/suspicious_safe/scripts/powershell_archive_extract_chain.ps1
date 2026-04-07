$url = "https://example.invalid/archive.zip"
$zip = "$env:TEMP\\sample.zip"
$dest = "$env:TEMP\\expanded"

Invoke-WebRequest -Uri $url -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $dest
Start-Process "$dest\\placeholder.exe"
# inert placeholder path only; no working payload
