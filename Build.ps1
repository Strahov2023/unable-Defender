[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$compilerCandidates = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $compiler) {
    throw 'Не найден встроенный компилятор .NET Framework csc.exe.'
}

$scriptPath = Join-Path $root 'DefenderControl.ps1'
$launcherTemplatePath = Join-Path $root 'src\Launcher.cs'
$objectDirectory = Join-Path $root 'obj'
$generatedLauncherPath = Join-Path $objectDirectory 'Launcher.generated.cs'
$outputPath = Join-Path $root 'DefenderControl.exe'

if (-not (Test-Path -LiteralPath $scriptPath)) { throw 'Не найден DefenderControl.ps1.' }
if (-not (Test-Path -LiteralPath $launcherTemplatePath)) { throw 'Не найден шаблон Launcher.cs.' }

$scriptHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToUpperInvariant()
$launcherTemplate = [System.IO.File]::ReadAllText($launcherTemplatePath, [System.Text.Encoding]::UTF8)
$marker = '__SCRIPT_SHA256__'
if (($launcherTemplate.Split(@($marker), [System.StringSplitOptions]::None).Count - 1) -ne 1) {
    throw 'Шаблон Launcher.cs должен содержать ровно один маркер SHA-256.'
}
$generatedLauncher = $launcherTemplate.Replace($marker, $scriptHash)

New-Item -ItemType Directory -Path $objectDirectory -Force | Out-Null
[System.IO.File]::WriteAllText($generatedLauncherPath, $generatedLauncher, [System.Text.UTF8Encoding]::new($true))

$arguments = @(
    '/nologo',
    '/target:winexe',
    '/platform:anycpu',
    '/optimize+',
    ('/win32manifest:{0}' -f (Join-Path $root 'src\app.manifest')),
    '/reference:System.dll',
    '/reference:System.Windows.Forms.dll',
    ('/out:{0}' -f $outputPath),
    $generatedLauncherPath
)

try {
    & $compiler $arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Компилятор завершился с кодом $LASTEXITCODE."
    }
}
finally {
    Remove-Item -LiteralPath $generatedLauncherPath -Force -ErrorAction SilentlyContinue
}

$exeHash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToUpperInvariant()
$integrityPath = Join-Path $root 'integrity.sha256'
@(
    "$scriptHash *DefenderControl.ps1",
    "$exeHash *DefenderControl.exe"
) | Set-Content -LiteralPath $integrityPath -Encoding ASCII

Write-Host "Собрано: DefenderControl.exe"
Write-Host "SHA-256 скрипта: $scriptHash"
Write-Host "SHA-256 EXE:     $exeHash"
