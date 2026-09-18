[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptRoot 'Config.psd1')
Import-Module (Join-Path $scriptRoot 'RdpAlerts.Common.psm1') -Force

$computerName = [Environment]::MachineName
$connection = Test-NetConnection $config.SmtpHost -Port $config.SmtpPort -WarningAction SilentlyContinue
if (-not $connection.TcpTestSucceeded) {
    $message = "No hay conexión TCP con $($config.SmtpHost):$($config.SmtpPort)."
    Write-RdpAlertsLog -Level ERROR -Message $message
    throw $message
}

$subject = "PRUEBA RDP $computerName"
$body = @"
Prueba de conexión SMTP desde $computerName.

Fecha: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Remitente: $($config.Sender)
Destinatario: $($config.Recipient)
"@

try {
    Send-RdpAlertEmail -Config $config -Subject $subject -Body $body
    Write-RdpAlertsLog -Level INFO -Message 'Correo de prueba enviado correctamente.'
    Write-Host 'Correo de prueba enviado correctamente.' -ForegroundColor Green
}
catch {
    $message = "Falló el correo de prueba: $($_.Exception.Message)"
    Write-RdpAlertsLog -Level ERROR -Message $message
    Write-Error $message
    exit 1
}
