# Сборка Lazeyka.exe: тесты, значок, PyInstaller, самопроверка готового exe.
# Ядер своего VPN в exe нет: Лазейка скачивает их с GitHub при запуске (docs/vpnclient-plan.md, 9).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "Нет .venv — см. README, раздел «Сборка из исходников»" }

Push-Location $root
try {
    $env:PYTHONIOENCODING = 'utf-8'
    Write-Host '== Тесты' -ForegroundColor Cyan
    & $py -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Тесты не прошли' }

    Write-Host '== Значок' -ForegroundColor Cyan
    & $py -c "import sys; sys.path.insert(0, '.'); from app import icons; icons.save_ico('assets/icon.ico')"
    if ($LASTEXITCODE -ne 0) { throw 'Значок не создан' }

    Write-Host '== PyInstaller' -ForegroundColor Cyan
    & $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build\work build\lazeyka.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller завершился с ошибкой' }

    Write-Host '== Самопроверка exe' -ForegroundColor Cyan
    $report = Join-Path $env:TEMP 'lazeyka-selftest.json'
    Remove-Item $report -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath (Join-Path $root 'dist\Lazeyka.exe') -ArgumentList @('--selftest', $report) -PassThru -Wait
    $result = Get-Content $report -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($check in $result.checks) {
        $mark = if ($check.ok) { 'OK ' } else { 'ERR' }
        Write-Host ("  {0} {1}: {2}" -f $mark, $check.name, $check.detail)
    }
    if ($proc.ExitCode -ne 0 -or -not $result.ok) { throw 'Самопроверка exe не прошла' }

    $size = (Get-Item (Join-Path $root 'dist\Lazeyka.exe')).Length / 1MB
    $hash = (Get-FileHash (Join-Path $root 'dist\Lazeyka.exe') -Algorithm SHA256).Hash
    Write-Host ("== Готово: dist\Lazeyka.exe, {0:N1} МБ, SHA-256 {1}" -f $size, $hash) -ForegroundColor Green
}
finally {
    Pop-Location
}
