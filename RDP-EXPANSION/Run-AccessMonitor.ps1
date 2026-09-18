[CmdletBinding()]
param(
    [switch]$Initialize
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptRoot 'Config.psd1')
Import-Module (Join-Path $scriptRoot 'RdpAlerts.Common.psm1') -Force

$computerName = [Environment]::MachineName
$dataDirectory = Get-RdpAlertsDataDirectory
$statePath = Join-Path $dataDirectory 'monitor-state.json'
$queuePath = Join-Path $dataDirectory 'pending-alerts.json'
$historyPath = Join-Path $dataDirectory 'access-history.csv'
$eventHistoryPath = Join-Path $dataDirectory 'event-history.csv'
$mutex = New-Object Threading.Mutex($false, 'Local\SAMBAccessMonitor')

if (-not $mutex.WaitOne(0)) {
    Write-RdpAlertsLog -Level INFO -Message 'Otra instancia del monitor sigue activa.'
    exit 0
}

function Save-JsonAtomic {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    $temporaryPath = "$Path.tmp"
    $json = ConvertTo-Json -InputObject $Value -Depth 8
    Set-Content -LiteralPath $temporaryPath -Value $json -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Get-LatestRecordId {
    param([Parameter(Mandatory)][string]$LogName)

    $event = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    return [long]$event.RecordId
}

function Get-FileLength {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return [long](Get-Item -LiteralPath $Path).Length
    }
    return [long]0
}

function Write-AuditEvent {
    param(
        [Parameter(Mandatory)][datetime]$Timestamp,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$EventType,
        [string]$User = '',
        [string]$Source = '',
        [string]$Details = '',
        [Parameter(Mandatory)][string]$SourceId,
        [bool]$EmailAlert = $false
    )

    [pscustomobject]@{
        Timestamp = $Timestamp.ToString('o')
        Method = $Method
        EventType = $EventType
        User = $User
        Source = $Source
        Details = $Details
        SourceId = $SourceId
        EmailAlert = $EmailAlert
    } | Export-Csv -LiteralPath $eventHistoryPath -Append -NoTypeInformation -Encoding UTF8
}

function Get-XmlChildValue {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$Name
    )

    $child = $Node.SelectSingleNode("*[local-name()='$Name']")
    if ($child) { return [string]$child.InnerText }
    return ''
}

function New-MonitorState {
    $securityRecordId = Get-LatestRecordId -LogName 'Security'
    $rdpRecordId = Get-LatestRecordId -LogName $config.RdpLogName
    $systemRecordId = Get-LatestRecordId -LogName $config.SystemLogName

    [pscustomobject]@{
        Version = 1
        RdpRecordId = $rdpRecordId
        SecurityRecordId = $securityRecordId
        SystemRecordId = $systemRecordId
        TeamViewerOffset = Get-FileLength -Path $config.TeamViewerLog
        AnyDeskOffset = Get-FileLength -Path $config.AnyDeskLog
        TeamViewerRemoteId = ''
        AnyDeskRemoteId = ''
        AnyDeskRemoteName = ''
        AnyDeskActiveId = ''
        AnyDeskActiveName = ''
        AnyDeskLastTimestamp = [datetime]::UtcNow.ToString('o')
        LastPowerTransition = ''
        UpdatedAt = (Get-Date).ToString('o')
    }
}

function Add-MissingStateProperties {
    param($State)

    foreach ($property in @{
        AnyDeskActiveId = ''
        AnyDeskActiveName = ''
        AnyDeskLastTimestamp = [datetime]::UtcNow.ToString('o')
        LastPowerTransition = ''
    }.GetEnumerator()) {
        if (-not $State.PSObject.Properties[$property.Key]) {
            $State | Add-Member -NotePropertyName $property.Key -NotePropertyValue $property.Value
        }
    }

    if (-not $State.PSObject.Properties['SystemRecordId']) {
        $State | Add-Member -NotePropertyName SystemRecordId `
            -NotePropertyValue (Get-LatestRecordId -LogName $config.SystemLogName)
    }
}

function Read-AppendedLines {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$Offset
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Lines = @(); Offset = [long]0 }
    }

    $fileLength = [long](Get-Item -LiteralPath $Path).Length
    if ($fileLength -lt $Offset) {
        $Offset = 0
    }

    $stream = New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite
    )

    try {
        [void]$stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            $text = $reader.ReadToEnd()
            $newOffset = [long]$stream.Position
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    $lines = if ($text) { @($text -split '\r?\n' | Where-Object { $_ }) } else { @() }
    [pscustomobject]@{ Lines = $lines; Offset = $newOffset }
}

function Get-EventData {
    param([Parameter(Mandatory)]$Event)

    [xml]$xml = $Event.ToXml()
    $values = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $values[[string]$node.Name] = [string]$node.InnerText
    }
    return $values
}

function Test-HumanAccount {
    param([string]$UserName)

    if ([string]::IsNullOrWhiteSpace($UserName) -or $UserName -eq '-') { return $false }
    if ($UserName.EndsWith('$')) { return $false }
    if ($UserName -match '^(DWM-|UMFD-)') { return $false }
    if ($UserName -in @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')) {
        return $false
    }
    return $true
}

function Test-RemoteRdpAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    return $Address -notin @('LOCAL', '127.0.0.1', '::1', 'localhost')
}

function New-AccessAlert {
    param(
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][ValidateSet(
            'RDP', 'TEAMVIEWER', 'ANYDESK', 'FISICAMENTE',
            'ENCENDIDO', 'APAGADO', 'APAGADO_REPENTINO', 'RESTAURAR', 'SUSPENDER'
        )][string]$Method,
        [Parameter(Mandatory)][datetime]$Timestamp,
        [string]$User = 'No disponible',
        [string]$Source = 'No disponible',
        [string]$Details = '',
        [Parameter(Mandatory)][string]$SourceId
    )

    $result = $Success.ToString()
    [pscustomobject]@{
        Id = "$Method|$result|$SourceId"
        Success = $Success
        Result = $result
        Method = $Method
        Timestamp = $Timestamp.ToString('o')
        Computer = $computerName
        User = $User
        Source = $Source
        Details = $Details
        SourceId = $SourceId
    }
}

function Test-AlertAlreadySent {
    param([Parameter(Mandatory)][string]$SourceId)

    if (-not (Test-Path -LiteralPath $historyPath)) { return $false }
    $existing = @(Import-Csv -LiteralPath $historyPath)
    return [bool]($existing | Where-Object { $_.SourceId -eq $SourceId })
}

function Add-AlertToQueue {
    param([Parameter(Mandatory)]$Alert)

    if (Test-AlertAlreadySent -SourceId $Alert.SourceId) { return }
    if (-not ($script:queue | Where-Object { $_.Id -eq $Alert.Id })) {
        $script:queue += $Alert
    }
}

function Get-LineTimestamp {
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][ValidateSet('TeamViewer', 'AnyDesk')][string]$Format
    )

    $pattern = if ($Format -eq 'TeamViewer') {
        '^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3})'
    }
    else {
        '^\s*\w+\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})'
    }

    if ($Line -match $pattern) {
        $dateFormat = if ($Format -eq 'TeamViewer') { 'yyyy/MM/dd HH:mm:ss.fff' } else { 'yyyy-MM-dd HH:mm:ss.fff' }
        $styles = if ($Format -eq 'AnyDesk') {
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal
        }
        else {
            [Globalization.DateTimeStyles]::None
        }
        $parsed = [datetime]::ParseExact(
            $Matches[1],
            $dateFormat,
            [Globalization.CultureInfo]::InvariantCulture,
            $styles
        )
        if ($Format -eq 'AnyDesk') { return $parsed.ToLocalTime() }
        return $parsed
    }
    return $null
}

function Collect-RdpAlerts {
    param($State)

    $eventIds = 'EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25 or EventID=39 or EventID=40 or EventID=41 or EventID=42'
    $xpath = "*[System[(($eventIds)) and (EventRecordID>$([long]$State.RdpRecordId))]]"
    $events = @(Get-WinEvent -LogName $config.RdpLogName -FilterXPath $xpath `
        -ErrorAction SilentlyContinue | Sort-Object RecordId)

    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $details = $xml.Event.UserData.EventXML
        $user = Get-XmlChildValue -Node $details -Name 'User'
        $source = Get-XmlChildValue -Node $details -Name 'Address'
        $session = Get-XmlChildValue -Node $details -Name 'SessionID'
        if (-not $session) { $session = Get-XmlChildValue -Node $details -Name 'Session' }
        if (-not $session) { $session = Get-XmlChildValue -Node $details -Name 'TargetSession' }
        $reason = Get-XmlChildValue -Node $details -Name 'Reason'

        $eventType = switch ($event.Id) {
            21 { 'LoginSuccess' }
            22 { 'ShellStarted' }
            23 { 'Logoff' }
            24 { 'Disconnected' }
            25 { 'Reconnected' }
            39 { 'DisconnectedBySession' }
            40 { 'DisconnectReason' }
            41 { 'ArbitrationStarted' }
            42 { 'ArbitrationEnded' }
        }
        $isRemoteRdp = Test-RemoteRdpAddress -Address $source
        # El 21 tambien dispara en consola fisica (Address=LOCAL). El correo de
        # RDP nuevo sale del 4624 LogonType 10, que incluye IP WAN.
        $sendEmail = ($event.Id -eq 25) -and $isRemoteRdp
        $description = "Evento $($event.Id); sesion $session"
        if ($reason) { $description += "; motivo $reason" }

        Write-AuditEvent -Timestamp $event.TimeCreated -Method RDP -EventType $eventType `
            -User $user -Source $source -Details $description `
            -SourceId "Rdp:$($event.RecordId)" -EmailAlert $sendEmail

        if ($sendEmail) {
            Add-AlertToQueue (New-AccessAlert -Success $true -Method RDP `
                -Timestamp $event.TimeCreated -User $user -Source $source `
                -Details $description -SourceId "Event:$($event.RecordId)")
        }
        $State.RdpRecordId = [long]$event.RecordId
    }
}

function Collect-SecurityAlerts {
    param($State)

    $latestRecordId = Get-LatestRecordId -LogName 'Security'
    $securityIds = 'EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4778 or EventID=4779 or EventID=4800 or EventID=4801'
    $xpath = "*[System[(($securityIds) and (EventRecordID>$([long]$State.SecurityRecordId)))]]"
    $events = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath `
        -ErrorAction SilentlyContinue | Sort-Object RecordId)

    foreach ($event in $events) {
        $data = Get-EventData -Event $event
        if ($event.Id -notin @(4624, 4625)) {
            $eventType = switch ($event.Id) {
                4634 { 'SessionLogoff' }
                4647 { 'UserInitiatedLogoff' }
                4778 { 'SessionReconnected' }
                4779 { 'SessionDisconnected' }
                4800 { 'WorkstationLocked' }
                4801 { 'WorkstationUnlocked' }
            }
            $sessionUser = if ($data.TargetUserName) {
                "$($data.TargetDomainName)\$($data.TargetUserName)"
            }
            elseif ($data.AccountName) {
                "$($data.AccountDomain)\$($data.AccountName)"
            }
            else {
                [string]$data.SubjectUserName
            }
            $sessionSource = if ($data.ClientAddress) {
                [string]$data.ClientAddress
            }
            elseif ($data.IpAddress) {
                [string]$data.IpAddress
            }
            else {
                [string]$data.WorkstationName
            }
            Write-AuditEvent -Timestamp $event.TimeCreated -Method WINDOWS_SESSION `
                -EventType $eventType -User $sessionUser -Source $sessionSource `
                -Details "Evento $($event.Id); sesion $($data.SessionName); LogonId $($data.TargetLogonId)" `
                -SourceId "Security:$($event.RecordId)"
            continue
        }

        $logonType = [string]$data.LogonType
        $user = [string]$data.TargetUserName
        if (-not (Test-HumanAccount -UserName $user)) { continue }

        $hasRemoteAddress = $data.IpAddress -and
            $data.IpAddress -notin @('-', '127.0.0.1', '::1')
        $isRemote = $logonType -eq '10' -or ($logonType -eq '7' -and $hasRemoteAddress)
        $method = if ($isRemote) { 'RDP' } else { 'FISICAMENTE' }
        $isRelevant = if ($logonType -eq '10') {
            $true
        }
        elseif ($method -eq 'RDP') {
            # Tipo 7 remoto: el correo de reconexion sale del evento 25.
            $event.Id -eq 4625
        }
        else {
            $logonType -in @('2', '7', '11')
        }
        if (-not $isRelevant) { continue }

        $source = if ($data.IpAddress -and $data.IpAddress -ne '-') {
            [string]$data.IpAddress
        }
        else {
            [string]$data.WorkstationName
        }

        $description = switch ($logonType) {
            '2' { 'Inicio interactivo local' }
            '7' { 'Desbloqueo local' }
            '10' { 'Inicio remoto RDP' }
            '11' { 'Inicio local con credenciales en cache' }
            default { "LogonType $logonType" }
        }

        Write-AuditEvent -Timestamp $event.TimeCreated -Method $method `
            -EventType $(if ($event.Id -eq 4624) { 'LoginSuccess' } else { 'LoginFailed' }) `
            -User "$($data.TargetDomainName)\$user" -Source $source `
            -Details "Evento $($event.Id); $description; estado $($data.Status)" `
            -SourceId "Security:$($event.RecordId)" -EmailAlert $true

        $securityAlertKey = 'Security:{0}:{1}:{2}:{3:yyyyMMddHHmmss}:{4}' -f `
            $event.Id, $logonType, $user, $event.TimeCreated, $source
        Add-AlertToQueue (New-AccessAlert -Success ($event.Id -eq 4624) -Method $method `
            -Timestamp $event.TimeCreated -User "$($data.TargetDomainName)\$user" `
            -Source $source -Details "Evento $($event.Id); $description; estado $($data.Status)" `
            -SourceId $securityAlertKey)
    }

    $State.SecurityRecordId = $latestRecordId
}

function Get-SystemPowerDefinition {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][string]$ProviderName,
        $Data,
        $State
    )

    switch ($EventId) {
        12 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-General') {
                return [pscustomobject]@{
                    Method = 'ENCENDIDO'; EventType = 'Startup'; Email = $true; Success = $true
                }
            }
        }
        13 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-General') {
                return [pscustomobject]@{
                    Method = 'APAGADO'; EventType = 'Shutdown'; Email = $false; Success = $true
                }
            }
        }
        41 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-Power') {
                return [pscustomobject]@{
                    Method = 'APAGADO_REPENTINO'; EventType = 'UnexpectedShutdown'; Email = $true; Success = $false
                }
            }
        }
        42 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-Power') {
                return [pscustomobject]@{
                    Method = 'SUSPENDER'; EventType = 'Sleep'; Email = $false; Success = $true
                }
            }
        }
        107 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-Power') {
                $wakeFromState = 0
                if ($Data -and $Data.WakeFromState) {
                    [void][int]::TryParse([string]$Data.WakeFromState, [ref]$wakeFromState)
                }
                $fromShutdown = $State -and [string]$State.LastPowerTransition -eq 'Shutdown'
                # Fast Startup: 1074 + 42 + 107 estado 5. Sleep real: 42 sin apagado.
                if ($fromShutdown -or $wakeFromState -ge 5) {
                    return [pscustomobject]@{
                        Method = 'ENCENDIDO'; EventType = 'Startup'; Email = $true; Success = $true
                    }
                }
                return [pscustomobject]@{
                    Method = 'RESTAURAR'; EventType = 'Resume'; Email = $true; Success = $true
                }
            }
        }
        109 {
            if ($ProviderName -eq 'Microsoft-Windows-Kernel-Power') {
                return [pscustomobject]@{
                    Method = 'APAGADO'; EventType = 'ShutdownTransition'; Email = $false; Success = $true
                }
            }
        }
        1074 {
            if ($ProviderName -eq 'User32') {
                return [pscustomobject]@{
                    Method = 'APAGADO'; EventType = 'ShutdownInitiated'; Email = $true; Success = $true
                }
            }
        }
        6005 {
            if ($ProviderName -eq 'EventLog') {
                return [pscustomobject]@{
                    Method = 'ENCENDIDO'; EventType = 'EventLogStarted'; Email = $false; Success = $true
                }
            }
        }
        6006 {
            if ($ProviderName -eq 'EventLog') {
                return [pscustomobject]@{
                    Method = 'APAGADO'; EventType = 'EventLogStopped'; Email = $false; Success = $true
                }
            }
        }
        6008 {
            if ($ProviderName -eq 'EventLog') {
                return [pscustomobject]@{
                    Method = 'APAGADO_REPENTINO'; EventType = 'PreviousShutdownUnexpected'; Email = $true; Success = $false
                }
            }
        }
    }
    return $null
}

function Get-SystemPowerDetails {
    param(
        [Parameter(Mandatory)]$Event,
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)]$Data
    )

    $parts = @("Evento $($Event.Id)", $Definition.EventType)
    switch ($Event.Id) {
        12 {
            if ($Data.StartTime) { $parts += "inicio $($Data.StartTime)" }
            if ($Data.BuildVersion) { $parts += "build $($Data.BuildVersion).$($Data.QfeVersion)" }
        }
        13 {
            if ($Data.StopTime) { $parts += "cierre $($Data.StopTime)" }
        }
        41 {
            $parts += "bugcheck $($Data.BugcheckCode)"
            if ($Data.PowerButtonTimestamp) { $parts += "powerButton $($Data.PowerButtonTimestamp)" }
        }
        42 {
            $parts += "motivo $($Data.Reason)"
        }
        107 {
            $parts += "desde estado $($Data.WakeFromState)"
        }
        109 {
            if ($Data.ShutdownActionType) { $parts += "accion $($Data.ShutdownActionType)" }
            if ($Data.ShutdownEventCode) { $parts += "codigo $($Data.ShutdownEventCode)" }
            if ($Data.ShutdownReason) { $parts += "motivo $($Data.ShutdownReason)" }
        }
        1074 {
            if ($Data.param5) { $parts += [string]$Data.param5 }
            if ($Data.param3) { $parts += [string]$Data.param3 }
            if ($Data.param1) { $parts += "proceso $($Data.param1)" }
        }
        6008 {
            $parts += 'el apagado anterior no fue limpio'
        }
    }
    return ($parts -join '; ')
}

function Collect-SystemPowerAlerts {
    param($State)

    $eventIds = 'EventID=12 or EventID=13 or EventID=41 or EventID=42 or EventID=107 or EventID=109 or EventID=1074 or EventID=6005 or EventID=6006 or EventID=6008'
    $xpath = "*[System[(($eventIds) and (EventRecordID>$([long]$State.SystemRecordId)))]]"
    $events = @(Get-WinEvent -LogName $config.SystemLogName -FilterXPath $xpath `
        -ErrorAction SilentlyContinue | Sort-Object RecordId)
    $startupEmailSent = $false

    foreach ($event in $events) {
        $data = @{}
        try { $data = Get-EventData -Event $event } catch { $data = @{} }

        $definition = Get-SystemPowerDefinition -EventId $event.Id -ProviderName $event.ProviderName `
            -Data $data -State $State
        $State.SystemRecordId = [long]$event.RecordId
        if (-not $definition) { continue }

        if ($definition.Method -eq 'ENCENDIDO' -and $definition.Email -and $startupEmailSent) {
            $definition.Email = $false
        }

        $user = if ($data.param7) { [string]$data.param7 } else { '' }
        $source = $event.ProviderName
        $description = Get-SystemPowerDetails -Event $event -Definition $definition -Data $data

        Write-AuditEvent -Timestamp $event.TimeCreated -Method $definition.Method `
            -EventType $definition.EventType -User $user -Source $source `
            -Details $description -SourceId "System:$($event.RecordId)" `
            -EmailAlert $definition.Email

        if ($definition.Email) {
            if ($definition.Method -eq 'ENCENDIDO') { $startupEmailSent = $true }
            Add-AlertToQueue (New-AccessAlert -Success $definition.Success -Method $definition.Method `
                -Timestamp $event.TimeCreated -User $(if ($user) { $user } else { 'No disponible' }) `
                -Source $source -Details $description -SourceId "System:$($event.RecordId)")
        }

        if ($event.Id -eq 1074) {
            $State.LastPowerTransition = 'Shutdown'
        }
        elseif ($event.Id -eq 42 -and [string]$State.LastPowerTransition -ne 'Shutdown') {
            $State.LastPowerTransition = 'Sleep'
        }
        elseif ($event.Id -eq 107 -or (
            $event.Id -eq 12 -and $event.ProviderName -eq 'Microsoft-Windows-Kernel-General'
        )) {
            $State.LastPowerTransition = ''
        }
    }
}

function Collect-TeamViewerAlerts {
    param($State)

    $read = Read-AppendedLines -Path $config.TeamViewerLog -Offset ([long]$State.TeamViewerOffset)
    foreach ($line in $read.Lines) {
        if ($line -match 'client hello received from (\d+)') {
            $remoteId = $Matches[1]
            if (-not $State.TeamViewerRemoteId) {
                $timestamp = Get-LineTimestamp -Line $line -Format TeamViewer
                if (-not $timestamp) { $timestamp = Get-Date }
                Write-AuditEvent -Timestamp $timestamp -Method TEAMVIEWER `
                    -EventType 'IncomingRequest' -User "TeamViewer ID $remoteId" `
                    -Source $remoteId -Details 'Solicitud entrante TeamViewer' `
                    -SourceId "TeamViewerRequest:$($timestamp.ToString('o')):$remoteId"
            }
            $State.TeamViewerRemoteId = $remoteId
        }

        $success = $null
        if ($line -match '(?i)authentication .* was successful') { $success = $true }
        if ($line -match '(?i)authentication .* was denied') { $success = $false }
        if ($null -eq $success) { continue }

        $timestamp = Get-LineTimestamp -Line $line -Format TeamViewer
        if (-not $timestamp) { $timestamp = Get-Date }
        $remoteId = if ($State.TeamViewerRemoteId) { $State.TeamViewerRemoteId } else { 'No disponible' }
        $timeKey = $timestamp.ToString('yyyyMMddHHmmss')
        Write-AuditEvent -Timestamp $timestamp -Method TEAMVIEWER `
            -EventType $(if ($success) { 'AuthenticationSuccess' } else { 'AuthenticationDenied' }) `
            -User "TeamViewer ID $remoteId" -Source $remoteId `
            -Details 'Autenticacion de control remoto TeamViewer' `
            -SourceId "TeamViewerAuth:${timeKey}:$success" -EmailAlert $true
        Add-AlertToQueue (New-AccessAlert -Success $success -Method TEAMVIEWER `
            -Timestamp $timestamp -User "TeamViewer ID $remoteId" -Source $remoteId `
            -Details 'Autenticacion de control remoto TeamViewer' `
            -SourceId "$timeKey|$success")
        $State.TeamViewerRemoteId = ''
    }
    $State.TeamViewerOffset = [long]$read.Offset
}

function Collect-AnyDeskAlerts {
    param($State)

    $read = Read-AppendedLines -Path $config.AnyDeskLog -Offset ([long]$State.AnyDeskOffset)
    $lastUtc = if ($State.AnyDeskLastTimestamp) {
        ([datetime]$State.AnyDeskLastTimestamp).ToUniversalTime()
    }
    else {
        [datetime]::UtcNow
    }
    $maxUtc = $lastUtc

    foreach ($line in $read.Lines) {
        $timestamp = Get-LineTimestamp -Line $line -Format AnyDesk
        if (-not $timestamp) { continue }

        $timestampUtc = $timestamp.ToUniversalTime()
        if ($timestampUtc -le $lastUtc) { continue }
        if ($timestampUtc -gt $maxUtc) { $maxUtc = $timestampUtc }

        if ($line -match 'Incoming session request:\s*(.+?)\s+\((\d+)\)') {
            $State.AnyDeskRemoteName = $Matches[1]
            $State.AnyDeskRemoteId = $Matches[2]
            Write-AuditEvent -Timestamp $timestamp -Method ANYDESK -EventType 'IncomingRequest' `
                -User $State.AnyDeskRemoteName -Source $State.AnyDeskRemoteId `
                -Details 'Solicitud entrante AnyDesk' `
                -SourceId "AnyDeskRequest:$($timestamp.ToString('o')):$($State.AnyDeskRemoteId)"
            continue
        }

        if ($line -match 'The socket was closed remotely') {
            Write-AuditEvent -Timestamp $timestamp -Method ANYDESK -EventType 'Disconnected' `
                -User $State.AnyDeskActiveName -Source $State.AnyDeskActiveId `
                -Details 'Sesion AnyDesk cerrada remotamente' `
                -SourceId "AnyDeskClose:$($timestamp.ToString('o'))"
            $State.AnyDeskActiveId = ''
            $State.AnyDeskActiveName = ''
            continue
        }

        $success = $null
        if ($line -match 'Session started \(ok\)') { $success = $true }
        if ($line -match '(?i)Session (?:request )?(?:denied|rejected|failed)') { $success = $false }
        if ($line -match '(?i)Session started \((?!ok\))') { $success = $false }
        if ($null -eq $success) { continue }
        if (-not $State.AnyDeskRemoteId) { continue }

        $remoteId = $State.AnyDeskRemoteId
        $remoteName = if ($State.AnyDeskRemoteName) { $State.AnyDeskRemoteName } else { 'No disponible' }
        $timeKey = $timestamp.ToString('yyyyMMddHHmmss')
        Write-AuditEvent -Timestamp $timestamp -Method ANYDESK `
            -EventType $(if ($success) { 'AuthenticationSuccess' } else { 'AuthenticationDenied' }) `
            -User $remoteName -Source $remoteId -Details 'Sesion remota AnyDesk' `
            -SourceId "AnyDeskAuth:${timeKey}:$success" -EmailAlert $true
        Add-AlertToQueue (New-AccessAlert -Success $success -Method ANYDESK `
            -Timestamp $timestamp -User $remoteName -Source $remoteId `
            -Details 'Sesion remota AnyDesk' -SourceId "$timeKey|$success")
        if ($success) {
            $State.AnyDeskActiveId = $remoteId
            $State.AnyDeskActiveName = $remoteName
        }
        $State.AnyDeskRemoteId = ''
        $State.AnyDeskRemoteName = ''
    }
    $State.AnyDeskOffset = [long]$read.Offset
    $State.AnyDeskLastTimestamp = $maxUtc.ToString('o')
}

function Send-PendingAlerts {
    $remaining = @()
    foreach ($alert in $script:queue) {
        try {
            $subjectPrefix = if ($alert.Method -in @(
                'ENCENDIDO', 'APAGADO', 'APAGADO_REPENTINO', 'RESTAURAR', 'SUSPENDER'
            )) {
                'Evento de estacion'
            }
            else {
                'Intento de inicio de sesion'
            }
            $bodyTitle = if ($subjectPrefix -eq 'Evento de estacion') {
                'ALERTA DE ESTACION'
            }
            else {
                'ALERTA DE ACCESO'
            }
            $subject = "$subjectPrefix - $($alert.Result) - $($alert.Method) - $($alert.Computer) | Hardware | Investments"
            $body = @"
$bodyTitle

Resultado: $($alert.Result)
Metodo: $($alert.Method)
Equipo: $($alert.Computer)
Usuario o ID: $($alert.User)
Fecha: $([datetime]$alert.Timestamp | Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Origen o ID remoto: $($alert.Source)
Detalle: $($alert.Details)
"@
            Send-RdpAlertEmail -Config $config -Subject $subject -Body $body
            $alert | Select-Object Timestamp, Result, Method, Computer, User, Source, Details, SourceId |
                Export-Csv -LiteralPath $historyPath -Append -NoTypeInformation -Encoding UTF8
            Write-RdpAlertsLog -Level INFO -Message "Alerta enviada: $($alert.Id)"
        }
        catch {
            $remaining += $alert
            Write-RdpAlertsLog -Level ERROR -Message "Alerta pendiente $($alert.Id): $($_.Exception.Message)"
        }
    }
    $script:queue = @($remaining)
    Save-JsonAtomic -Value $script:queue -Path $queuePath
}

try {
    if ($Initialize) {
        $state = New-MonitorState
        Save-JsonAtomic -Value $state -Path $statePath
        Save-JsonAtomic -Value @() -Path $queuePath
        Write-RdpAlertsLog -Level INFO -Message 'Monitor inicializado en el estado actual.'
        Write-Host 'Monitor inicializado. Los eventos historicos no generaran alertas.' -ForegroundColor Green
        exit 0
    }

    if (-not (Test-Path -LiteralPath $statePath)) {
        throw 'El monitor no esta inicializado. Ejecute Install-AccessMonitorTask.ps1 como administrador.'
    }

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Add-MissingStateProperties -State $state
    $script:queue = if (Test-Path -LiteralPath $queuePath) {
        @(Get-Content -LiteralPath $queuePath -Raw | ConvertFrom-Json)
    }
    else {
        @()
    }

    Collect-RdpAlerts -State $state
    Collect-SecurityAlerts -State $state
    Collect-SystemPowerAlerts -State $state
    Collect-TeamViewerAlerts -State $state
    Collect-AnyDeskAlerts -State $state
    $state.UpdatedAt = (Get-Date).ToString('o')
    Save-JsonAtomic -Value $state -Path $statePath
    Save-JsonAtomic -Value $script:queue -Path $queuePath
    Send-PendingAlerts
}
catch {
    Write-RdpAlertsLog -Level ERROR -Message "Fallo general del monitor: $($_.Exception.Message)"
    Write-Error $_
    exit 1
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
