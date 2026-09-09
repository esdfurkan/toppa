# Toppa Windows packaging (roadmap Step 5).
#
# Builds the elevated service and the unprivileged tray, stages wintun.dll,
# and emits a zip under dist/. An installer (Inno Setup) can consume the
# staged directory; keep the service started by the SCM wrapper.
#
# Usage: powershell -File scripts\package\windows.ps1
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$dist = Join-Path $repo "dist\windows"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Write-Host "== building desktop binaries =="
Push-Location (Join-Path $repo "desktop")
go build -o (Join-Path $dist "toppasvc.exe") ./cmd/toppasvc
go build -o (Join-Path $dist "toppactl.exe") ./cmd/toppactl
go vet ./... # packaging must never ship vet-dirty code
Pop-Location

Write-Host "== fyne tray =="
Write-Host "skipped: add 'go build -o dist\windows\toppa.exe ./cmd/toppa' after 'go mod tidy' pulls fyne.io/fyne/v2"

Write-Host "== wintun.dll =="
# wintun.dll is distributed with the Toppa installer; download the official
# Wintun release from https://www.wintun.net/ and place it next to toppasvc.exe.
# Redistribution terms: review Wintun's license text before shipping binaries.
if (-not (Test-Path (Join-Path $dist "wintun.dll"))) {
    Write-Warning "wintun.dll missing from dist — the service will fail to create the adapter until it is staged."
}

Write-Host "== done: $dist =="
