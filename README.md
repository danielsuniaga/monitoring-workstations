# Alertas de acceso — WSOFISAMBMAIN

Primera versión para probar Gmail SMTP y leer inicios de sesión RDP exitosos.

## 1. Revocar la contraseña expuesta

Elimine en Google la contraseña de aplicación compartida anteriormente y cree una nueva.
No guarde ni comparta esa contraseña en texto plano.

## 2. Guardar la credencial cifrada

Abra **Windows PowerShell con el mismo usuario que ejecutará la tarea programada**:

```powershell
Set-Location 'C:\Users\WSOFIDEVELOPERMENT\SAMB\DOCUMENTATION\RDP'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Setup-GmailCredential.ps1
```

Pegue la nueva contraseña de aplicación sin espacios. Windows la cifra con DPAPI; solo
el mismo usuario de Windows en este equipo puede recuperarla.

## 3. Probar el correo

```powershell
.\Test-Email.ps1
```

El script comprueba primero el puerto 587, fuerza TLS 1.2 y registra el resultado en:

```text
%LOCALAPPDATA%\SAMB\RdpAlerts\rdp-alerts.log
```

Si Gmail responde `5.7.0 Authentication Required`, las causas más probables son una
contraseña de aplicación incorrecta/revocada o haber utilizado la contraseña normal.

## 4. Probar la lectura de eventos RDP

Para mostrar los eventos 21 de las últimas 24 horas sin enviar correos:

```powershell
.\Test-RdpEventDetection.ps1
```

Para consultar los últimos siete días:

```powershell
.\Test-RdpEventDetection.ps1 -SinceMinutes 10080
```

## 5. Instalar el monitor automatico

Abra **Windows PowerShell como administrador** y ejecute:

```powershell
Set-Location 'C:\Users\WSOFIDEVELOPERMENT\SAMB\DOCUMENTATION\RDP'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-AccessMonitorTask.ps1
```

El instalador pedira la contrasena de **Windows** de `WSOFIDEVELOPER\WSOFIDEVELOPERMENT`. No use el
PIN de Windows Hello ni la contrasena de Gmail. Esta credencial permite ejecutar la
tarea aunque no haya una sesion abierta y queda protegida por el Programador de tareas.

El instalador:

1. Habilita la auditoria de inicios correctos y fallidos.
2. Guarda la posicion actual de cada registro para no alertar eventos historicos.
3. Crea la tarea `SAMB - Monitor de accesos`.
4. Ejecuta el monitor cada minuto con privilegios elevados.

## Alertas implementadas

- RDP correcto: evento 4624 con `LogonType = 10` (incluye IP WAN).
- RDP reconectado: evento 25 de LocalSessionManager.
- RDP fallido: evento 4625 con `LogonType = 10`.
- Acceso fisico correcto o fallido: eventos 4624/4625 con tipos 2, 7 local y 11.
- TeamViewer correcto o denegado: log de TeamViewer y resultado de autenticacion.
- AnyDesk correcto: `Session started (ok)`.
- AnyDesk fallido: solo marcadores explicitos de sesion denegada, rechazada o fallida.
- Encendido: evento 12 de Kernel-General, o evento 107 tras un apagado (Fast Startup).
- Apagado o reinicio pedido: evento 1074. Correo `True - APAGADO`.
- Apagado repentino: eventos 41 o 6008. Correo `False - APAGADO_REPENTINO`.
- Restaurar de suspension: evento 107 solo despues de un sleep real. Correo `True - RESTAURAR`.
- Suspender: evento 42. Solo historial.

El detalle completo de eventos, correlaciones y exclusiones esta en `EVENT-MAP.md`.

El asunto de accesos tiene el formato:

```text
Intento de inicio de sesion - True - RDP - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - False - TEAMVIEWER - WSOFISAMBMAIN | Hardware | Investments
```

El asunto de energia usa el mismo pie, con otro prefijo:

```text
Evento de estacion - True - ENCENDIDO - WSOFISAMBMAIN | Hardware | Investments
Evento de estacion - False - APAGADO_REPENTINO - WSOFISAMBMAIN | Hardware | Investments
```

`WSOFISAMBMAIN` es obtenido automaticamente mediante el nombre local de Windows; no
esta hardcodeado en la configuracion.

## Datos y diagnostico

Los datos se guardan en:

```text
%LOCALAPPDATA%\SAMB\RdpAlerts
```

Archivos principales:

- `access-history.csv`: alertas enviadas.
- `rdp-alerts.log`: actividad y errores.
- `monitor-state.json`: ultima posicion procesada.
- `pending-alerts.json`: correos que deben reintentarse.

TeamViewer y AnyDesk pueden usar servidores intermediarios. Sus logs normalmente
permiten conocer el ID remoto y a veces el nombre, pero no garantizan la IP real del
equipo que origino la conexion.
