[CmdletBinding()]
param(
    [ValidateRange(1, 10080)]
    [int]$SinceMinutes = 1440,

    [ValidateRange(1, 1000)]
    [int]$MaxEvents = 20
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptRoot 'Config.psd1')
$startTime = (Get-Date).AddMinutes(-$SinceMinutes)

$events = Get-WinEvent -FilterHashtable @{
    LogName = $config.RdpLogName
    Id = 21
    StartTime = $startTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "No se encontraron eventos RDP 21 en los últimos $SinceMinutes minutos."
    exit 0
}

$events | ForEach-Object {
    $event = $_
    [xml]$xml = $event.ToXml()
    $details = $xml.Event.UserData.EventXML

    [pscustomobject]@{
        Fecha = $event.TimeCreated
        Equipo = $event.MachineName
        Usuario = [string]$details.User
        Sesion = [string]$details.SessionID
        IPOrigen = [string]$details.Address
        Evento = $event.Id
        RecordId = $event.RecordId
    }
} | Format-Table -AutoSize
