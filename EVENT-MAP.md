# Mapa de auditoria de accesos

Este documento separa los eventos que generan correo de los eventos que solo se
conservan en `event-history.csv`. No todos los eventos tecnicos representan un nuevo
acceso; enviar un correo por cada uno produciria varias alertas por una sola conexion.

## RDP - TerminalServices LocalSessionManager

- **21 - LoginSuccess:** inicio RDP nuevo y correcto. Envia correo `True`.
- **22 - ShellStarted:** inicio del escritorio/shell de la sesion. Solo historial.
- **23 - Logoff:** cierre completo de la sesion. Solo historial.
- **24 - Disconnected:** sesion desconectada sin cerrarla. Solo historial.
- **25 - Reconnected:** regreso a una sesion RDP existente. Envia correo `True`.
- **39 - DisconnectedBySession:** una sesion desconecto a otra. Solo historial.
- **40 - DisconnectReason:** desconexion con codigo de motivo. Solo historial.
- **41 - ArbitrationStarted:** Windows comienza a decidir que sesion debe activarse.
  Solo historial.
- **42 - ArbitrationEnded:** finaliza el arbitraje de sesion. Solo historial.
- **32:** inicializacion interna de RDSAppXPlugin. Diagnostico, no se procesa.
- **36:** error de transicion del escritorio bloqueado. Diagnostico, no se procesa.
- **54:** apagado del administrador de sesiones. Diagnostico, no se procesa.
- **59:** consulta interna de capacidades de sesion. Diagnostico, no se procesa.

El evento 1149 de RemoteConnectionManager no existe actualmente en este equipo, por
lo que no se usa como fuente principal.

## Windows Security

- **4624:** autenticacion correcta.
  - `LogonType 2`: inicio interactivo local. Correo `True - FISICAMENTE`.
  - `LogonType 7`: desbloqueo. Si contiene una IP remota se considera parte de RDP y
    no duplica el correo del evento 25; sin IP remota se considera fisico.
  - `LogonType 10`: acceso remoto. El exito se toma de RDP 21/25 para evitar duplicados.
  - `LogonType 11`: inicio local con credenciales en cache. Correo `True - FISICAMENTE`.
- **4625:** autenticacion fallida.
  - Tipos 10 o 7 con IP remota: correo `False - RDP`.
  - Tipos 2, 7 local y 11: correo `False - FISICAMENTE`.
- **4634:** una sesion termino. Solo historial.
- **4647:** el usuario inicio el cierre de sesion. Solo historial.
- **4778:** reconexion de sesion. Solo historial; RDP 25 es la alerta principal.
- **4779:** desconexion de sesion. Solo historial; RDP 24 es la fuente principal.
- **4800:** estacion bloqueada. Solo historial.
- **4801:** estacion desbloqueada. Solo historial.

Otros tipos de 4624/4625, como red, servicio, lote y cuentas tecnicas, se excluyen para
evitar alertas por servicios de Windows, impresoras, recursos compartidos y tareas.

## TeamViewer 15.81.5

Fuente: `C:\Program Files (x86)\TeamViewer\TeamViewer15_Logfile.log`.

- Solicitud entrante y TeamViewer ID remoto: solo historial.
- Autenticacion aceptada: correo `True - TEAMVIEWER`.
- Autenticacion denegada: correo `False - TEAMVIEWER`.
- Eventos de relay, keep-alive e IPC local: excluidos porque no prueban un acceso.
- El cierre remoto no tiene un marcador estable en la muestra actual; no se genera
  correo ni se infiere a partir del cierre de una conexion relay.

## AnyDesk 9.0.14

Fuente: `C:\Users\WSOFIDEVELOPERMENT\AppData\Roaming\AnyDesk\ad.trace`.

- `Incoming session request`: solicitud con nombre e ID remoto. Solo historial.
- `Session started (ok)`: correo `True - ANYDESK`, solo si hubo una solicitud
  entrante previa en el mismo ciclo.
- Rechazo, denegacion o fallo explicito de sesion: correo `False - ANYDESK`.
- `The socket was closed remotely`: cierre de sesion. Solo historial.
- Errores de proxy, discovery o relay: excluidos porque no son intentos de acceso.
- Si `ad.trace` se recorta o se reescribe (AnyDesk lo hace al abrir sesion), el
  monitor no reenvia sesiones historicas: ignora lineas con marca de tiempo ya
  vista y no duplica `SourceId` presentes en `access-history.csv`.

## Energia y ciclo de vida - registro System

No todos estos eventos son un acceso. Se mapean para saber si la estacion se
encendio, se suspendio, se restauro o se apago de forma limpia o brusca.

- **12 Kernel-General - Startup:** el sistema operativo arranco. Correo
  `True - ENCENDIDO`. Se ignora el evento 12 de Wininit (LSASS), que no es un
  arranque.
- **13 Kernel-General - Shutdown:** el sistema operativo se esta cerrando.
  Solo historial; el correo de apagado sale de 1074.
- **1074 User32 - ShutdownInitiated:** alguien o Windows pidio apagar o
  reiniciar. Incluye usuario, proceso y motivo. Correo `True - APAGADO`.
- **109 Kernel-Power - ShutdownTransition:** transicion interna de apagado o
  reinicio. Solo historial.
- **6005 EventLog:** el registro de eventos arranco. Solo historial; el correo
  de encendido sale del 12.
- **6006 EventLog:** el registro de eventos se detuvo. Solo historial.
- **41 Kernel-Power - UnexpectedShutdown:** el arranque actual sigue a un
  corte sucio (kernel power). Correo `False - APAGADO_REPENTINO`.
- **6008 EventLog - PreviousShutdownUnexpected:** el apagado anterior no fue
  limpio. Correo `False - APAGADO_REPENTINO`.
- **42 Kernel-Power - Sleep:** la estacion entra en suspension. Solo historial
  `SUSPENDER` para no alertar cada descanso corto.
- **107 Kernel-Power - Resume:** la estacion se reanuda de suspension. Correo
  `True - RESTAURAR`.

Se excluyen 6013 (uptime periodico al mediodia), 172, 187, 40, 566, 577 y 578
de Kernel-Power: diagnostico interno, no un cambio de estacion.

## Asuntos de correo

```text
Intento de inicio de sesion - True - RDP - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - False - RDP - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - True - TEAMVIEWER - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - False - TEAMVIEWER - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - True - ANYDESK - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - False - ANYDESK - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - True - FISICAMENTE - WSOFISAMBMAIN | Hardware | Investments
Intento de inicio de sesion - False - FISICAMENTE - WSOFISAMBMAIN | Hardware | Investments
Evento de estacion - True - ENCENDIDO - WSOFISAMBMAIN | Hardware | Investments
Evento de estacion - True - APAGADO - WSOFISAMBMAIN | Hardware | Investments
Evento de estacion - False - APAGADO_REPENTINO - WSOFISAMBMAIN | Hardware | Investments
Evento de estacion - True - RESTAURAR - WSOFISAMBMAIN | Hardware | Investments
```

El nombre mostrado se obtiene de `[Environment]::MachineName` en cada ejecucion. Los
ejemplos usan el nombre actual de esta estacion, no un valor fijo del monitor.

## Persistencia y control de duplicados

- `monitor-state.json` guarda el ultimo EventRecordID (RDP, Security y System)
  y la posicion de cada log.
- `pending-alerts.json` conserva correos pendientes si Gmail no responde.
- `access-history.csv` registra los correos enviados.
- `event-history.csv` registra el ciclo de vida completo aunque no genere correo.
- `rdp-alerts.log` registra ejecuciones y errores.
- Los eventos Security equivalentes del mismo usuario, segundo, origen y tipo se
  agrupan para evitar correos duplicados.

TeamViewer y AnyDesk pueden ocultar la IP real mediante servidores relay. En esos casos
se registra el ID remoto disponible, no se inventa una IP.
