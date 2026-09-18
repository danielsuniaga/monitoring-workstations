Set-StrictMode -Version Latest

function Get-RdpAlertsDataDirectory {
    $path = Join-Path $env:LOCALAPPDATA 'SAMB\RdpAlerts'
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    return $path
}

function Get-RdpAlertsCredentialPath {
    Join-Path (Get-RdpAlertsDataDirectory) 'gmail-credential.xml'
}

function Write-RdpAlertsLog {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $logPath = Join-Path (Get-RdpAlertsDataDirectory) 'rdp-alerts.log'
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Send-RdpAlertEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$Body
    )

    $credentialPath = Get-RdpAlertsCredentialPath
    if (-not (Test-Path -LiteralPath $credentialPath)) {
        throw "No existe la credencial SMTP. Ejecute primero Setup-GmailCredential.ps1."
    }

    $credential = Import-Clixml -LiteralPath $credentialPath -ErrorAction Stop
    if ($credential.UserName -ne $Config.Sender) {
        throw "La credencial almacenada no corresponde al remitente configurado."
    }

    # Windows PowerShell 5.1 puede negociar protocolos antiguos si no se fuerza TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12

    $mail = New-Object Net.Mail.MailMessage
    $smtp = New-Object Net.Mail.SmtpClient($Config.SmtpHost, [int]$Config.SmtpPort)

    try {
        $mail.From = $Config.Sender
        [void]$mail.To.Add($Config.Recipient)
        $mail.Subject = $Subject
        $mail.SubjectEncoding = [Text.Encoding]::UTF8
        $mail.Body = $Body
        $mail.BodyEncoding = [Text.Encoding]::UTF8
        $mail.IsBodyHtml = $false

        $smtp.EnableSsl = $true
        $smtp.UseDefaultCredentials = $false
        $smtp.Credentials = $credential.GetNetworkCredential()
        $smtp.Timeout = 30000
        $smtp.Send($mail)
    }
    finally {
        $mail.Dispose()
        $smtp.Dispose()
    }
}

Export-ModuleMember -Function Get-RdpAlertsDataDirectory, Get-RdpAlertsCredentialPath,
    Send-RdpAlertEmail, Write-RdpAlertsLog
