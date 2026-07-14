[CmdletBinding()]
param(
    [switch]$RequireSignature
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Add-Pass([string]$Message) { Write-Host "[PASS] $Message" -ForegroundColor Green }
function Add-Failure([string]$Message) { $script:failures.Add($Message); Write-Host "[FAIL] $Message" -ForegroundColor Red }
function Add-Warning([string]$Message) { $script:warnings.Add($Message); Write-Host "[WARN] $Message" -ForegroundColor Yellow }

Write-Host 'Defender Control — защитные тесты' -ForegroundColor Cyan

foreach ($file in Get-ChildItem -LiteralPath $root -Filter '*.ps1') {
    $tokens = $null
    $errors = $null
    $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
    [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -eq 0) { Add-Pass "Синтаксис: $($file.Name)" }
    else { Add-Failure "Синтаксис $($file.Name): $($errors[0].Message)" }
}

$scriptPath = Join-Path $root 'DefenderControl.ps1'
$exePath = Join-Path $root 'DefenderControl.exe'
$launcherPath = Join-Path $root 'src\Launcher.cs'
$manifestPath = Join-Path $root 'src\app.manifest'

$scriptContent = [System.IO.File]::ReadAllText($scriptPath, [System.Text.Encoding]::UTF8)
$formsLoadIndex = $scriptContent.IndexOf('Add-Type -AssemblyName System.Windows.Forms', [StringComparison]::Ordinal)
$firstFormsTypeIndex = $scriptContent.IndexOf('[System.Windows.Forms.', [StringComparison]::Ordinal)
if (($formsLoadIndex -ge 0) -and ($firstFormsTypeIndex -ge 0) -and ($formsLoadIndex -lt $firstFormsTypeIndex)) {
    Add-Pass 'WinForms загружается до объявления типизированных функций.'
}
else {
    Add-Failure 'System.Windows.Forms должен загружаться до первого использования WinForms-типа.'
}

if (-not (Test-Path -LiteralPath $exePath)) {
    Add-Failure 'DefenderControl.exe отсутствует.'
}
else {
    try {
        $assembly = [Reflection.Assembly]::LoadFrom($exePath)
        $launcherType = $assembly.GetType('Launcher', $true)
        $field = $launcherType.GetField('ExpectedScriptSha256', [Reflection.BindingFlags]'Static,NonPublic')
        $pinnedHash = [string]$field.GetRawConstantValue()
        $actualHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToUpperInvariant()

        if ($pinnedHash -eq $actualHash) { Add-Pass 'EXE привязан к текущему SHA-256 скрипта.' }
        else { Add-Failure "EXE ожидает $pinnedHash, скрипт имеет $actualHash." }

        $temporaryFile = [IO.Path]::GetTempFileName()
        try {
            [IO.File]::WriteAllBytes($temporaryFile, [IO.File]::ReadAllBytes($scriptPath))
            [IO.File]::AppendAllText($temporaryFile, '# tamper-test')
            $tamperedHash = (Get-FileHash -LiteralPath $temporaryFile -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($tamperedHash -ne $pinnedHash) { Add-Pass 'Намеренная подмена одного фрагмента обнаруживается.' }
            else { Add-Failure 'Тест подмены не изменил контрольную сумму.' }
        }
        finally { Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue }

        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
        if ($version.FileVersion -eq '1.3.0.0') { Add-Pass 'Версия EXE: 1.3.0.0.' }
        else { Add-Failure "Неожиданная версия EXE: $($version.FileVersion)." }
    }
    catch { Add-Failure "Не удалось проверить EXE: $($_.Exception.Message)" }

    $signature = Get-AuthenticodeSignature -LiteralPath $exePath
    if ($signature.Status -eq 'Valid') { Add-Pass 'Цифровая подпись EXE действительна.' }
    elseif ($RequireSignature) { Add-Failure "Подпись EXE обязательна, статус: $($signature.Status)." }
    else { Add-Warning "EXE пока не подписан доверенным сертификатом: $($signature.Status)." }
}

$launcherSource = [IO.File]::ReadAllText($launcherPath, [Text.Encoding]::UTF8)
$requiredLauncherGuards = @(
    'ExpectedScriptSha256',
    'FixedTimeEquals',
    'FileShare.Read',
    'RejectReparsePoint',
    'SetDefaultDllDirectories',
    'FileSystemRights.FullControl'
)
foreach ($guard in $requiredLauncherGuards) {
    if ($launcherSource.Contains($guard)) { Add-Pass "Защита лаунчера присутствует: $guard" }
    else { Add-Failure "В лаунчере отсутствует защита: $guard" }
}

$manifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8)
if ($manifest.Contains('level="requireAdministrator"')) { Add-Pass 'Манифест требует повышение прав до запуска логики.' }
else { Add-Failure 'В манифесте отсутствует requireAdministrator.' }

$filesToScan = @(
    (Join-Path $root 'DefenderControl.ps1'),
    (Join-Path $root 'src\Launcher.cs')
)
$bannedPatterns = @(
    ('Invoke-' + 'Expression'),
    ('Download' + 'String'),
    ('Download' + 'File'),
    ('FromBase64' + 'String'),
    ('Reflection.Assembly' + '::Load'),
    ('ExecutionPolicy\s+' + 'Bypass'),
    ('Add-MpPreference.*' + 'Exclusion'),
    ('Set-MpPreference.*' + 'Exclusion')
)
foreach ($file in $filesToScan) {
    $content = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)
    foreach ($pattern in $bannedPatterns) {
        if ($content -match $pattern) { Add-Failure "Запрещённый шаблон '$pattern' найден в $(Split-Path $file -Leaf)." }
    }
}
if (-not $failures.Count) { Add-Pass 'Динамическая загрузка, загрузка из сети, Bypass и самоисключения не найдены.' }

Write-Host "`nИтог: $($failures.Count) ошибок, $($warnings.Count) предупреждений."
if ($failures.Count) {
    foreach ($failure in $failures) { Write-Host " - $failure" -ForegroundColor Red }
    exit 1
}
exit 0
