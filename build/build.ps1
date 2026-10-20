# Сборка Lazeyka.exe: тесты, значок, PyInstaller, самопроверка готового exe.
# Ядер своего VPN в exe нет: Лазейка скачивает их с GitHub при запуске (docs/vpnclient-plan.md, 9).
# -Dist — другая папка exe: собрать, пока запущена Лазейка из dist (её exe занят).
# Сеть сборке не нужна: сетевые тесты (GitHub, Telegram) — только с -Online. Статическая проверка конфигов
# настоящими ядрами идёт всегда (zip ядер — в vendor\cores, README «Сборка из исходников»); -NoCoreCheck — без неё.
param([string]$Dist = 'dist', [switch]$Online, [switch]$NoCoreCheck)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "Нет .venv — см. README, раздел «Сборка из исходников»" }
$testSwitches = 'LAZEYKA_NO_NETWORK', 'LAZEYKA_CORE_CHECK'
$savedEnv = @{}
foreach ($name in $testSwitches) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

Push-Location $root
try {
    $env:PYTHONIOENCODING = 'utf-8'
    Write-Host '== Проверка проверок' -ForegroundColor Cyan
    # Зелёный прогон обязан уметь стать красным: заведомо падающий тест и пропуск не по переключателю
    # окружения должны завершить pytest с кодом 1 (CODING_STANDARDS, «Главное правило»).
    foreach ($canary in 'tests\canary\must_fail.py', 'tests\canary\stray_skip.py') {
        & $py -m pytest -q -p no:cacheprovider --allow-skips network $canary | Out-Null
        if ($LASTEXITCODE -ne 1) { throw "Контрольный $canary завершился с кодом $LASTEXITCODE, а не 1: итогу тестов верить нельзя" }
    }

    Write-Host '== Тесты' -ForegroundColor Cyan
    # Пропуск допустим только по названным переключателям, любой другой проваливает прогон (tests/conftest.py).
    $allowedSkips = @('core_e2e')                   # живой прогон ядер — вручную, не в сборке
    if ($Online) { $env:LAZEYKA_NO_NETWORK = $null } else { $env:LAZEYKA_NO_NETWORK = '1'; $allowedSkips += 'network' }
    if ($NoCoreCheck) { $env:LAZEYKA_CORE_CHECK = $null; $allowedSkips += 'core_check' } else { $env:LAZEYKA_CORE_CHECK = '1' }
    & $py -m pytest -q --allow-skips ($allowedSkips -join ',')
    if ($LASTEXITCODE -ne 0) { throw 'Тесты не прошли (или пропущено то, чего сборка не разрешала, — список выше)' }

    Write-Host '== Значок' -ForegroundColor Cyan
    & $py -c "import sys; sys.path.insert(0, '.'); from app import icons; icons.save_ico('assets/icon.ico')"
    if ($LASTEXITCODE -ne 0) { throw 'Значок не создан' }

    Write-Host '== PyInstaller' -ForegroundColor Cyan
    # PyInstaller ищет DLL зависимостей по PATH: посторонние папки (JDK, Git и т. п.) подкладывали в exe
    # свои копии MSVCP140 и api-ms-win-*. На время сборки — только Windows и сам Python.
    $pyHome = Split-Path -Parent (& $py -c "import sys; print(sys._base_executable)")
    $savedPath = $env:PATH
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$pyHome;$(Join-Path $root '.venv\Scripts')"
    try {
        & $py -m PyInstaller --noconfirm --clean --distpath $Dist --workpath build\work build\lazeyka.spec
    }
    finally {
        $env:PATH = $savedPath
    }
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller завершился с ошибкой' }

    # Проверку окна (LAZEYKA_UI_SELFCHECK, docs/architecture.md) сборка не запускает: ей нужен рабочий стол,
    # а при запущенной Лазейке второй экземпляр только передал бы управление первому. Замок навигации
    # проверяют тесты (tests/test_guards.py).
    Write-Host '== Самопроверка exe' -ForegroundColor Cyan
    $report = Join-Path $env:TEMP 'lazeyka-selftest.json'
    Remove-Item $report -ErrorAction SilentlyContinue
    $exe = Join-Path (Join-Path $root $Dist) 'Lazeyka.exe'
    # Одной строкой и в кавычках: массив Start-Process склеивает через пробел, и путь с пробелом
    # (%TEMP% в профиле «Иван Петров») разорвался бы на два аргумента.
    $proc = Start-Process -FilePath $exe -ArgumentList ('--selftest "{0}"' -f $report) -PassThru -Wait
    $result = Get-Content $report -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($check in $result.checks) {
        $mark = if ($check.ok) { 'OK ' } else { 'ERR' }
        Write-Host ("  {0} {1}: {2}" -f $mark, $check.name, $check.detail)
    }
    if ($proc.ExitCode -ne 0 -or -not $result.ok) { throw 'Самопроверка exe не прошла' }

    $size = (Get-Item $exe).Length / 1MB
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash
    Write-Host ("== Готово: {0}, {1:N1} МБ, SHA-256 {2}" -f $exe, $size, $hash) -ForegroundColor Green
}
finally {
    Pop-Location
    foreach ($name in $testSwitches) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
}
