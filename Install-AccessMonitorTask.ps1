[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    throw 'Abra Windows PowerShell como administrador y vuelva a ejecutar este script.'
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptRoot 'Config.psd1')
$monitorPath = Join-Path $scriptRoot 'Run-AccessMonitor.ps1'
$taskUser = "$env:USERDOMAIN\$env:USERNAME"

Write-Host 'Habilitando auditoria de inicios correctos y fallidos...'
$logonSubcategory = '{0CCE9215-69AE-11D9-BED3-505054503030}'
& auditpol.exe /set "/subcategory:$logonSubcategory" /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) {
    throw "auditpol termino con codigo $LASTEXITCODE."
}

Write-Host 'Inicializando posiciones para no enviar eventos historicos...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $monitorPath -Initialize
if ($LASTEXITCODE -ne 0) {
    throw 'No fue posible inicializar el monitor.'
}

Write-Host ''
Write-Host "La tarea debe ejecutarse como $taskUser aunque nadie tenga la sesion abierta."
Write-Host 'Introduzca la contrasena de WINDOWS de esa cuenta; no use el PIN ni la contrasena de Gmail.'
$windowsCredential = Get-Credential -UserName $taskUser -Message 'Credencial de Windows para la tarea programada'

if ($windowsCredential.UserName -ne $taskUser) {
    throw "La cuenta debe ser exactamente $taskUser para poder descifrar la credencial de Gmail."
}

$passwordPointer = [IntPtr]::Zero
try {
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $windowsCredential.Password
    )
    $windowsPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)

    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$monitorPath`""
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments `
        -WorkingDirectory $scriptRoot

    # En esta version de Windows los disparadores diarios no crean el objeto
    # Repetition. Un disparador unico admite el intervalo directamente.
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $config.TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Description 'Alertas de acceso RDP, TeamViewer, AnyDesk, local y energia.' `
        -User $taskUser -Password $windowsPassword -RunLevel Highest -Force | Out-Null
}
finally {
    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $windowsPassword = $null
}

Start-ScheduledTask -TaskName $config.TaskName
Write-Host ''
Write-Host "Tarea '$($config.TaskName)' instalada e iniciada correctamente." -ForegroundColor Green
Write-Host 'El monitor revisara nuevos accesos cada minuto.'
