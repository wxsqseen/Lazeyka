# Файлы релиза на GitHub: <Dist>\release\ — Lazeyka.exe, Lazeyka-browser.zip и SHA256SUMS.txt. Запускать после build.ps1.
# Ядер своего VPN в exe нет (решение владельца 2026-10-18): Лазейка скачивает официальные релизы
# sing-box и Xray прямо с их страниц на GitHub, сама их не распространяет — поэтому ни текста GPL-3.0,
# ни архивов исходников ядер к релизу не прикладываем (docs/vpnclient-plan.md, раздел 9).
# -Dist — та же папка, что у build.ps1 -Dist.
param([string]$Dist = 'dist')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path (Join-Path $root $Dist) 'Lazeyka.exe'
if (-not (Test-Path $exe)) { throw "Нет $exe — сначала build\build.ps1" }

$out = Join-Path (Join-Path $root $Dist) 'release'
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $exe $out
# Расширение «Лазейка для браузера» — архивом рядом с exe (ставится распакованным, README внутри).
# Имена в архиве — с «/» явно: Compress-Archive и ZipFile в Windows PowerShell 5.1 пишут «\», и не всякий
# распаковщик создаст тогда папку icons.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extDir = Join-Path $root 'browser-extension'
$zip = [System.IO.Compression.ZipFile]::Open((Join-Path $out 'Lazeyka-browser.zip'), 'Create')
try {
    Get-ChildItem $extDir -Recurse -File | ForEach-Object {
        $name = $_.FullName.Substring($extDir.Length + 1).Replace('\', '/')
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $name)
    }
} finally {
    $zip.Dispose()
}

$sums = Get-ChildItem $out -File | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
[System.IO.File]::WriteAllLines((Join-Path $out 'SHA256SUMS.txt'), [string[]]$sums)
Write-Host "== Готово: $out" -ForegroundColor Green
$sums | ForEach-Object { Write-Host "  $_" }
