[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptRoot 'Config.psd1')
Import-Module (Join-Path $scriptRoot 'RdpAlerts.Common.psm1') -Force

Write-Host 'Introduzca la NUEVA contraseña de aplicación de Gmail, sin espacios.'
Write-Host 'No introduzca la contraseña normal de la cuenta.'
$securePassword = Read-Host -Prompt "Contraseña de aplicación para $($config.Sender)" -AsSecureString
$credential = New-Object Management.Automation.PSCredential($config.Sender, $securePassword)
$credentialPath = Get-RdpAlertsCredentialPath

$credential | Export-Clixml -LiteralPath $credentialPath -Force

Write-Host ''
Write-Host "Credencial guardada cifrada en: $credentialPath" -ForegroundColor Green
Write-Host 'Solo el mismo usuario de Windows, en este mismo equipo, puede descifrarla.'
Write-Host 'La tarea programada deberá ejecutarse con este mismo usuario.'
