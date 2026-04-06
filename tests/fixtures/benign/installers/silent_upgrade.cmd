@echo off
set VERSION_URL=https://updates.example.local/projectx/version.txt
set ARCHIVE_URL=https://updates.example.local/projectx/archive.zip
echo Checking installed version
if exist "%ProgramFiles%\\ProjectX\\projectx.exe" echo Found installed copy
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%VERSION_URL%' -OutFile '%TEMP%\\projectx_version.txt'"
echo Silent upgrade would continue after validation
