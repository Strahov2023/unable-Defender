[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:AppName = 'Defender Control'
$script:AppVersion = '1.3.0'
$script:TaskName = 'DefenderControl-AutoReenable'
$script:ReenableAt = $null
$script:RefreshTicks = 0
$script:Mutex = $null
$script:LogDirectory = Join-Path $env:LOCALAPPDATA 'DefenderControl'
$script:LogPath = Join-Path $script:LogDirectory 'DefenderControl.log'
$script:LogPrepared = $false
$script:LastDefenderEnabled = $null
$script:AllowExit = $false
$script:NotifyIcon = $null
$script:DefenderModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1'
$script:ScheduledTasksModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\ScheduledTasks\ScheduledTasks.psd1'

# Загружаем привилегированные модули только из защищённого системного каталога.
foreach ($trustedModule in @($script:DefenderModulePath, $script:ScheduledTasksModulePath)) {
    if (Test-Path -LiteralPath $trustedModule) {
        Import-Module -Name $trustedModule -Force -ErrorAction Stop
    }
}
$PSModuleAutoLoadingPreference = 'None'

function Write-AppLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    try {
        if (-not (Test-Path -LiteralPath $script:LogDirectory)) {
            New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
        }
        if (-not $script:LogPrepared) {
            $script:LogPrepared = $true
            if ((Test-Path -LiteralPath $script:LogPath) -and ((Get-Item -LiteralPath $script:LogPath).Length -gt 1MB)) {
                $oldLog = "$($script:LogPath).old"
                Move-Item -LiteralPath $script:LogPath -Destination $oldLog -Force
            }
        }
        $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    }
    catch {
        # Ошибка журнала не должна мешать защитным операциям.
    }
}

function Show-TrayNotification {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Text,
        [System.Windows.Forms.ToolTipIcon]$Icon = [System.Windows.Forms.ToolTipIcon]::Info
    )

    if ($null -ne $script:NotifyIcon) {
        $script:NotifyIcon.BalloonTipTitle = $Title
        $script:NotifyIcon.BalloonTipText = $Text
        $script:NotifyIcon.BalloonTipIcon = $Icon
        $script:NotifyIcon.ShowBalloonTip(4000)
    }
}

function Get-DiagnosticsText {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Defender Control $($script:AppVersion)")
    $lines.Add("Время: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))")
    $lines.Add("PowerShell: $($PSVersionTable.PSVersion)")
    $lines.Add("Администратор: $(Test-Administrator)")

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $lines.Add("Windows: $($os.Caption), $($os.Version), build $($os.BuildNumber)")
    }
    catch { $lines.Add("Windows: не удалось определить") }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $lines.Add("Defender RealTimeProtectionEnabled: $($status.RealTimeProtectionEnabled)")
        $lines.Add("Defender AntivirusEnabled: $($status.AntivirusEnabled)")
        $lines.Add("Defender AMServiceEnabled: $($status.AMServiceEnabled)")
        $lines.Add("Defender IsTamperProtected: $($status.IsTamperProtected)")
        $lines.Add("Defender EngineVersion: $($status.AMEngineVersion)")
        $lines.Add("Defender SignatureVersion: $($status.AntivirusSignatureVersion)")
    }
    catch { $lines.Add("Defender status error: $($_.Exception.Message)") }

    $taskTime = Get-ReenableTaskTime
    $lines.Add("Auto-reenable task: $(if ($null -eq $taskTime) { 'нет' } else { $taskTime.ToString('yyyy-MM-dd HH:mm:ss') })")

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
        $lines.Add("Script signature: $($signature.Status)")
    }
    catch { $lines.Add('Script signature: недоступно') }

    $lines.Add("Log: $($script:LogPath)")
    return ($lines -join [Environment]::NewLine)
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-AsAdministrator {
    $arguments = '-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "{0}"' -f $PSCommandPath
    $powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $powershellPath -Verb RunAs -ArgumentList $arguments | Out-Null
}

function Show-Message {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Title = $script:AppName,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )

    [System.Windows.Forms.MessageBox]::Show(
        $Text,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $Icon
    ) | Out-Null
}

function Show-AppError {
    param(
        [Parameter(Mandatory = $true)][string]$Context,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $details = if ($null -ne $ErrorRecord) { $ErrorRecord.Exception.Message } else { 'Неизвестная ошибка' }
    Write-AppLog -Level ERROR -Message ("{0}: {1}" -f $Context, $details)
    Show-Message -Title 'Ошибка' -Icon Error -Text ("{0}`n`n{1}`n`nЖурнал: {2}" -f $Context, $details, $script:LogPath)
}

function Test-DefenderAvailable {
    return ($null -ne (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) -and
           ($null -ne (Get-Command Set-MpPreference -ErrorAction SilentlyContinue))
}

function Get-ReenableTaskTime {
    try {
        $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop
        if ($task.State -eq 'Disabled') {
            return $null
        }
        $info = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction Stop
        if ($info.NextRunTime -gt (Get-Date '2000-01-01')) {
            return [datetime]$info.NextRunTime
        }
    }
    catch {
        return $null
    }
    return $null
}

function Remove-ReenableTask {
    try {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction Stop
        Write-AppLog -Message 'Задание автоматического включения удалено.'
    }
    catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
        # Задание уже отсутствует.
    }
    catch {
        if ($null -ne (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue)) {
            throw
        }
    }
    $script:ReenableAt = $null
}

function New-ReenableTask {
    param([Parameter(Mandatory = $true)][ValidateRange(1, 1440)][int]$Minutes)

    if ($null -eq (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        throw 'Компонент Планировщика заданий недоступен.'
    }

    Remove-ReenableTask
    $when = (Get-Date).AddMinutes($Minutes)
    $powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskCommand = "Import-Module '$($script:DefenderModulePath)' -Force -ErrorAction Stop; Import-Module '$($script:ScheduledTasksModulePath)' -Force -ErrorAction Stop; try { Set-MpPreference -DisableRealtimeMonitoring `$false -ErrorAction Stop } finally { Unregister-ScheduledTask -TaskName '$($script:TaskName)' -Confirm:`$false -ErrorAction SilentlyContinue }"
    $taskArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -Command "{0}"' -f $taskCommand

    $action = New-ScheduledTaskAction -Execute $powershellPath -Argument $taskArguments
    $trigger = New-ScheduledTaskTrigger -Once -At $when
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Автоматически включает защиту Microsoft Defender в реальном времени.' -Force | Out-Null

    $verifiedTime = Get-ReenableTaskTime
    if ($null -eq $verifiedTime) {
        Remove-ReenableTask
        throw 'Не удалось проверить задание автоматического включения.'
    }

    $script:ReenableAt = $verifiedTime
    Write-AppLog -Message ("Создано автоматическое включение на {0:yyyy-MM-dd HH:mm:ss}." -f $verifiedTime)
}

function Set-ControlsBusy {
    param([bool]$Busy)
    $script:DisableButton.Enabled = -not $Busy
    $script:EnableButton.Enabled = -not $Busy
    $script:DurationBox.Enabled = -not $Busy
    $script:RefreshButton.Enabled = -not $Busy
    $script:Form.UseWaitCursor = $Busy
    [System.Windows.Forms.Application]::DoEvents()
}

function Wait-DefenderRealTimeState {
    param(
        [Parameter(Mandatory = $true)][bool]$ExpectedEnabled,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $current = [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
            if ($current -eq $ExpectedEnabled) {
                return $true
            }
        }
        catch {
            Write-AppLog -Level WARN -Message ("Промежуточная проверка состояния не удалась: {0}" -f $_.Exception.Message)
        }

        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    return $false
}

function Update-Countdown {
    if ($null -eq $script:ReenableAt) {
        $script:CountdownLabel.Text = 'Автовключение не запланировано'
        $script:CountdownLabel.ForeColor = [System.Drawing.Color]::DimGray
        return
    }

    $remaining = $script:ReenableAt - (Get-Date)
    if ($remaining.TotalSeconds -le 0) {
        $script:CountdownLabel.Text = 'Выполняется автоматическое включение...'
        $script:CountdownLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        return
    }

    $hours = [math]::Floor($remaining.TotalHours)
    $script:CountdownLabel.Text = 'Автовключение через {0:00}:{1:00}:{2:00}' -f $hours, $remaining.Minutes, $remaining.Seconds
    $script:CountdownLabel.ForeColor = [System.Drawing.Color]::DarkOrange
}

function Update-DefenderStatus {
    try {
        if (-not (Test-DefenderAvailable)) {
            throw 'Командлеты Microsoft Defender отсутствуют. Возможно, используется другой антивирус.'
        }

        $status = Get-MpComputerStatus -ErrorAction Stop
        $isEnabled = [bool]$status.RealTimeProtectionEnabled

        if (($null -ne $script:LastDefenderEnabled) -and ($script:LastDefenderEnabled -ne $isEnabled)) {
            if ($isEnabled) {
                Show-TrayNotification -Title 'Microsoft Defender' -Text 'Защита в реальном времени включена.' -Icon Info
            }
            else {
                Show-TrayNotification -Title 'Microsoft Defender' -Text 'Защита временно отключена. Автовключение запланировано.' -Icon Warning
            }
        }
        $script:LastDefenderEnabled = $isEnabled

        if ($isEnabled) {
            $script:StatusLabel.Text = '● Защита в реальном времени включена'
            $script:StatusLabel.ForeColor = [System.Drawing.Color]::ForestGreen
            $script:DisableButton.Enabled = $true
            $script:EnableButton.Enabled = $false
            if ($null -ne $script:ReenableAt) {
                Remove-ReenableTask
            }
        }
        else {
            $script:StatusLabel.Text = '● Защита в реальном времени отключена'
            $script:StatusLabel.ForeColor = [System.Drawing.Color]::Firebrick
            $script:DisableButton.Enabled = $false
            $script:EnableButton.Enabled = $true
        }

        if ($status.PSObject.Properties.Name -contains 'IsTamperProtected') {
            $script:TamperLabel.Text = if ($status.IsTamperProtected) { 'Защита от подделки: включена' } else { 'Защита от подделки: отключена' }
        }
        else {
            $script:TamperLabel.Text = 'Защита от подделки: состояние недоступно'
        }
        $script:TamperLabel.ForeColor = [System.Drawing.Color]::DimGray
    }
    catch {
        $script:StatusLabel.Text = 'Не удалось получить состояние Defender'
        $script:StatusLabel.ForeColor = [System.Drawing.Color]::Firebrick
        $script:TamperLabel.Text = $_.Exception.Message
        $script:TamperLabel.ForeColor = [System.Drawing.Color]::DimGray
        $script:DisableButton.Enabled = $false
        $script:EnableButton.Enabled = $false
        Write-AppLog -Level WARN -Message ("Ошибка чтения состояния Defender: {0}" -f $_.Exception.Message)
    }
    Update-Countdown
}

function Update-SmartAppControlStatus {
    try {
        $policyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        $state = Get-ItemPropertyValue -Path $policyPath -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop
        switch ([int]$state) {
            0 { $script:SmartAppStatusLabel.Text = '● Отключено'; $script:SmartAppStatusLabel.ForeColor = [System.Drawing.Color]::Firebrick }
            1 { $script:SmartAppStatusLabel.Text = '● Включено'; $script:SmartAppStatusLabel.ForeColor = [System.Drawing.Color]::ForestGreen }
            2 { $script:SmartAppStatusLabel.Text = '● Режим оценки'; $script:SmartAppStatusLabel.ForeColor = [System.Drawing.Color]::DarkOrange }
            default { $script:SmartAppStatusLabel.Text = "Неизвестное состояние ($state)"; $script:SmartAppStatusLabel.ForeColor = [System.Drawing.Color]::DimGray }
        }
    }
    catch {
        $script:SmartAppStatusLabel.Text = 'Недоступно в этой версии Windows'
        $script:SmartAppStatusLabel.ForeColor = [System.Drawing.Color]::DimGray
    }
}

function Update-AllStatuses {
    $storedTime = Get-ReenableTaskTime
    if ($null -ne $storedTime) {
        $script:ReenableAt = $storedTime
    }
    Update-DefenderStatus
    Update-SmartAppControlStatus
    $script:LastRefreshLabel.Text = 'Обновлено: {0:HH:mm:ss}' -f (Get-Date)
}

function Initialize-Interface {
    $script:Form = New-Object System.Windows.Forms.Form
    $script:Form.Text = "$($script:AppName) $($script:AppVersion)"
    $script:Form.ClientSize = New-Object System.Drawing.Size(520, 430)
    $script:Form.StartPosition = 'CenterScreen'
    $script:Form.FormBorderStyle = 'FixedDialog'
    $script:Form.MaximizeBox = $false
    $script:Form.MinimizeBox = $true
    $script:Form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = 'Защита Microsoft Defender'
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(24, 18)
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 16)

    $script:RefreshButton = New-Object System.Windows.Forms.Button
    $script:RefreshButton.Text = 'Обновить'
    $script:RefreshButton.Location = New-Object System.Drawing.Point(398, 18)
    $script:RefreshButton.Size = New-Object System.Drawing.Size(96, 32)

    $script:StatusLabel = New-Object System.Windows.Forms.Label
    $script:StatusLabel.Text = 'Проверка состояния...'
    $script:StatusLabel.AutoSize = $true
    $script:StatusLabel.Location = New-Object System.Drawing.Point(27, 65)

    $script:TamperLabel = New-Object System.Windows.Forms.Label
    $script:TamperLabel.Text = 'Защита от подделки: проверка...'
    $script:TamperLabel.AutoSize = $true
    $script:TamperLabel.Location = New-Object System.Drawing.Point(27, 91)
    $script:TamperLabel.ForeColor = [System.Drawing.Color]::DimGray

    $script:CountdownLabel = New-Object System.Windows.Forms.Label
    $script:CountdownLabel.Text = 'Автовключение не запланировано'
    $script:CountdownLabel.AutoSize = $true
    $script:CountdownLabel.Location = New-Object System.Drawing.Point(27, 117)
    $script:CountdownLabel.ForeColor = [System.Drawing.Color]::DimGray

    $durationLabel = New-Object System.Windows.Forms.Label
    $durationLabel.Text = 'Отключить на:'
    $durationLabel.AutoSize = $true
    $durationLabel.Location = New-Object System.Drawing.Point(27, 156)

    $script:DurationBox = New-Object System.Windows.Forms.ComboBox
    $script:DurationBox.Location = New-Object System.Drawing.Point(142, 152)
    $script:DurationBox.Size = New-Object System.Drawing.Size(145, 30)
    $script:DurationBox.DropDownStyle = 'DropDownList'
    [void]$script:DurationBox.Items.Add('5 минут')
    [void]$script:DurationBox.Items.Add('15 минут')
    [void]$script:DurationBox.Items.Add('30 минут')
    [void]$script:DurationBox.Items.Add('60 минут')
    $script:DurationBox.SelectedIndex = 1

    $script:DisableButton = New-Object System.Windows.Forms.Button
    $script:DisableButton.Text = 'Временно отключить'
    $script:DisableButton.Location = New-Object System.Drawing.Point(27, 198)
    $script:DisableButton.Size = New-Object System.Drawing.Size(220, 40)

    $script:EnableButton = New-Object System.Windows.Forms.Button
    $script:EnableButton.Text = 'Включить сейчас'
    $script:EnableButton.Location = New-Object System.Drawing.Point(274, 198)
    $script:EnableButton.Size = New-Object System.Drawing.Size(220, 40)

    $separator = New-Object System.Windows.Forms.Label
    $separator.BorderStyle = 'Fixed3D'
    $separator.Location = New-Object System.Drawing.Point(27, 262)
    $separator.Size = New-Object System.Drawing.Size(467, 2)

    $smartAppTitleLabel = New-Object System.Windows.Forms.Label
    $smartAppTitleLabel.Text = 'Интеллектуальное управление приложениями'
    $smartAppTitleLabel.AutoSize = $true
    $smartAppTitleLabel.Location = New-Object System.Drawing.Point(27, 282)
    $smartAppTitleLabel.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)

    $script:SmartAppStatusLabel = New-Object System.Windows.Forms.Label
    $script:SmartAppStatusLabel.Text = 'Проверка состояния...'
    $script:SmartAppStatusLabel.AutoSize = $true
    $script:SmartAppStatusLabel.Location = New-Object System.Drawing.Point(27, 313)

    $smartAppButton = New-Object System.Windows.Forms.Button
    $smartAppButton.Text = 'Открыть настройки Windows'
    $smartAppButton.Location = New-Object System.Drawing.Point(274, 300)
    $smartAppButton.Size = New-Object System.Drawing.Size(220, 38)

    $logButton = New-Object System.Windows.Forms.Button
    $logButton.Text = 'Открыть журнал'
    $logButton.Location = New-Object System.Drawing.Point(27, 369)
    $logButton.Size = New-Object System.Drawing.Size(145, 32)

    $diagnosticsButton = New-Object System.Windows.Forms.Button
    $diagnosticsButton.Text = 'Скопировать диагностику'
    $diagnosticsButton.Location = New-Object System.Drawing.Point(182, 369)
    $diagnosticsButton.Size = New-Object System.Drawing.Size(190, 32)

    $script:LastRefreshLabel = New-Object System.Windows.Forms.Label
    $script:LastRefreshLabel.Text = 'Обновлено: —'
    $script:LastRefreshLabel.AutoSize = $true
    $script:LastRefreshLabel.Location = New-Object System.Drawing.Point(382, 377)
    $script:LastRefreshLabel.ForeColor = [System.Drawing.Color]::DimGray

    $script:DisableButton.Add_Click({
        $minutes = @(5, 15, 30, 60)[$script:DurationBox.SelectedIndex]
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Отключить защиту в реальном времени на $minutes мин.?`n`nПеред отключением будет создано системное задание для автоматического включения. Не открывайте неизвестные файлы, пока защита отключена.",
            'Подтверждение', 'YesNo', 'Warning'
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        Set-ControlsBusy $true
        try {
            New-ReenableTask -Minutes $minutes
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            if (-not (Wait-DefenderRealTimeState -ExpectedEnabled $false -TimeoutSeconds 15)) {
                Remove-ReenableTask
                throw 'Windows не подтвердила отключение за 15 секунд. Изменение может блокироваться системной политикой, другим антивирусом или защитой от подделки.'
            }
            Write-AppLog -Message ("Защита в реальном времени отключена на $minutes мин.")
        }
        catch {
            try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
            try { Remove-ReenableTask } catch {}
            Show-AppError -Context 'Не удалось безопасно отключить защиту.' -ErrorRecord $_
        }
        finally {
            Set-ControlsBusy $false
            Update-AllStatuses
        }
    })

    $script:EnableButton.Add_Click({
        Set-ControlsBusy $true
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            if (-not (Wait-DefenderRealTimeState -ExpectedEnabled $true -TimeoutSeconds 15)) {
                throw 'Windows не подтвердила включение защиты за 15 секунд.'
            }
            Remove-ReenableTask
            Write-AppLog -Message 'Защита в реальном времени включена вручную.'
        }
        catch {
            Show-AppError -Context 'Не удалось включить защиту.' -ErrorRecord $_
        }
        finally {
            Set-ControlsBusy $false
            Update-AllStatuses
        }
    })

    $script:RefreshButton.Add_Click({ Update-AllStatuses })

    $smartAppButton.Add_Click({
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Будут открыты настройки Smart App Control.`n`nНа некоторых версиях Windows после отключения функцию нельзя включить обратно без сброса или переустановки системы. Продолжить?",
            'Важное предупреждение', 'YesNo', 'Warning'
        )
        if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) {
            try { Start-Process 'windowsdefender://Appbrowser' }
            catch {
                try { Start-Process 'windowsdefender:' }
                catch { Show-AppError -Context 'Не удалось открыть «Безопасность Windows».' -ErrorRecord $_ }
            }
        }
    })

    $logButton.Add_Click({
        try {
            if (-not (Test-Path -LiteralPath $script:LogPath)) {
                Write-AppLog -Message 'Журнал создан.'
            }
            $notepadPath = Join-Path $env:SystemRoot 'System32\notepad.exe'
            Start-Process -FilePath $notepadPath -ArgumentList ('"{0}"' -f $script:LogPath)
        }
        catch { Show-AppError -Context 'Не удалось открыть журнал.' -ErrorRecord $_ }
    })

    $diagnosticsButton.Add_Click({
        try {
            $diagnostics = Get-DiagnosticsText
            [System.Windows.Forms.Clipboard]::SetText($diagnostics)
            Write-AppLog -Message 'Диагностические сведения скопированы в буфер обмена.'
            Show-TrayNotification -Title $script:AppName -Text 'Диагностика скопирована в буфер обмена.'
            Show-Message -Text 'Диагностические сведения скопированы в буфер обмена.'
        }
        catch { Show-AppError -Context 'Не удалось собрать диагностику.' -ErrorRecord $_ }
    })

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.SetToolTip($script:DisableButton, 'Отключает только защиту в реальном времени и заранее создаёт автовключение.')
    $toolTip.SetToolTip($script:EnableButton, 'Немедленно включает защиту и удаляет ожидающее задание.')
    $toolTip.SetToolTip($diagnosticsButton, 'Копирует безопасный технический отчёт без персональных файлов.')

    $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $showMenuItem = $trayMenu.Items.Add('Открыть Defender Control')
    $enableMenuItem = $trayMenu.Items.Add('Включить защиту сейчас')
    [void]$trayMenu.Items.Add('-')
    $exitMenuItem = $trayMenu.Items.Add('Выход')

    $script:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:NotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
    $script:NotifyIcon.Text = 'Defender Control'
    $script:NotifyIcon.ContextMenuStrip = $trayMenu
    $script:NotifyIcon.Visible = $true

    $showWindow = {
        $script:Form.Show()
        $script:Form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $script:Form.Activate()
    }
    $showMenuItem.Add_Click($showWindow)
    $script:NotifyIcon.Add_DoubleClick($showWindow)
    $enableMenuItem.Add_Click({
        if ($script:EnableButton.Enabled) { $script:EnableButton.PerformClick() }
        else { Show-TrayNotification -Title $script:AppName -Text 'Защита уже включена.' }
    })
    $exitMenuItem.Add_Click({
        $script:AllowExit = $true
        $script:Form.Close()
    })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick({
        Update-Countdown
        $script:RefreshTicks++
        if ($script:RefreshTicks -ge 10) {
            $script:RefreshTicks = 0
            Update-AllStatuses
        }
    })

    $script:Form.Controls.AddRange(@(
        $titleLabel, $script:RefreshButton, $script:StatusLabel, $script:TamperLabel,
        $script:CountdownLabel, $durationLabel, $script:DurationBox,
        $script:DisableButton, $script:EnableButton, $separator, $smartAppTitleLabel,
        $script:SmartAppStatusLabel, $smartAppButton, $logButton, $diagnosticsButton, $script:LastRefreshLabel
    ))

    $script:Form.Add_Shown({
        Write-AppLog -Message ("Запуск версии {0}." -f $script:AppVersion)
        Update-AllStatuses
        $timer.Start()
    })
    $script:Form.Add_Resize({
        if ($script:Form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
            $script:Form.Hide()
            Show-TrayNotification -Title $script:AppName -Text 'Программа продолжает работать в области уведомлений.'
        }
    })
    $script:Form.Add_FormClosing({
        param($sender, $eventArgs)
        if ((-not $script:AllowExit) -and ($script:LastDefenderEnabled -eq $false)) {
            $taskText = if ($null -ne $script:ReenableAt) { "Автовключение запланировано на $($script:ReenableAt.ToString('HH:mm:ss'))." } else { 'Задание автовключения не найдено.' }
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Защита сейчас отключена. $taskText`n`nЗакрыть приложение?",
                'Защита отключена', 'YesNo', 'Warning'
            )
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
                $eventArgs.Cancel = $true
            }
        }
    })
    $script:Form.Add_FormClosed({
        $timer.Stop()
        $script:NotifyIcon.Visible = $false
        $script:NotifyIcon.Dispose()
        Write-AppLog -Message 'Окно закрыто.'
        if ($null -ne $script:Mutex) {
            try { $script:Mutex.ReleaseMutex() } catch {}
            $script:Mutex.Dispose()
        }
    })

    [void][System.Windows.Forms.Application]::Run($script:Form)
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    if (-not (Test-Administrator)) {
        try { Restart-AsAdministrator }
        catch { Show-Message -Text 'Запуск отменён. Для управления Microsoft Defender нужны права администратора.' -Icon Warning }
        exit
    }

    $createdNew = $false
    $script:Mutex = [System.Threading.Mutex]::new($true, 'Local\DefenderControl-8A6AC6EC', [ref]$createdNew)
    if (-not $createdNew) {
        Show-Message -Text 'Defender Control уже запущен.' -Icon Information
        exit
    }

    Initialize-Interface
}
catch {
    Write-AppLog -Level ERROR -Message ("Критическая ошибка: {0}" -f $_.Exception.ToString())
    try { Show-Message -Title 'Критическая ошибка' -Icon Error -Text ("Не удалось запустить Defender Control.`n`n{0}`n`nЖурнал: {1}" -f $_.Exception.Message, $script:LogPath) }
    catch {}
    exit 1
}
