[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Thumbprint,
    [ValidateNotNullOrEmpty()][string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $normalizedThumbprint | Select-Object -First 1

if (-not $certificate) { throw 'Сертификат не найден в Cert:\CurrentUser\My.' }
if (-not $certificate.HasPrivateKey) { throw 'У сертификата отсутствует закрытый ключ.' }
if ($certificate.NotAfter -le (Get-Date)) { throw 'Срок действия сертификата истёк.' }
if ($certificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1') { throw 'Для Smart App Control требуется RSA-сертификат, а не ECC.' }

$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$hasCodeSigningEku = $false
foreach ($extension in $certificate.Extensions) {
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        if ($extension.EnhancedKeyUsages | Where-Object Value -eq $codeSigningOid) { $hasCodeSigningEku = $true }
    }
}
if (-not $hasCodeSigningEku) { throw 'Сертификат не предназначен для подписи кода.' }

$scriptPath = Join-Path $root 'DefenderControl.ps1'
$exePath = Join-Path $root 'DefenderControl.exe'
if (-not (Test-Path -LiteralPath $exePath)) { throw 'Сначала выполните Build.ps1.' }

$scriptSignature = Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
if ($scriptSignature.Status -ne 'Valid') { throw "Не удалось подписать скрипт: $($scriptSignature.StatusMessage)" }

$signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction Stop |
    Where-Object FullName -Match '\\x64\\signtool\.exe$' |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signTool) { throw 'Не найден x64 SignTool из Windows SDK.' }

& $signTool.FullName sign /sha1 $normalizedThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /d 'Defender Control' $exePath
if ($LASTEXITCODE -ne 0) { throw "SignTool завершился с кодом $LASTEXITCODE." }

& $signTool.FullName verify /pa /v $exePath
if ($LASTEXITCODE -ne 0) { throw 'Проверка подписи EXE завершилась ошибкой.' }

Write-Host 'EXE и PowerShell-скрипт подписаны и проверены.'
