# NexFix — memoria del proyecto

> Este archivo es la memoria viva del proyecto. Quien retome el trabajo
> (persona o asistente) debe leerlo primero y **actualizarlo al terminar cada
> sesión**: estado, decisiones nuevas y próximos pasos. Detalle ampliado en
> [`docs/`](docs/).

## Qué es

App de escritorio para Windows que analiza y mantiene un PC gamer:

- **Resumen**: puntuación de salud y recomendaciones accionables (insights).
- **Componentes**: CPU, RAM (módulos, velocidad real vs. nominal: EXPO/XMP),
  GPU (VRAM real, driver), placa/BIOS, monitores (Hz actuales vs. máximos),
  uso en vivo y procesos que más consumen.
- **Discos y M.2**: discos físicos, bus (NVMe/SATA), salud, SMART NVMe
  completo (temperatura, desgaste, TB escritos, horas, errores), TRIM,
  pagefile/hiberfil, herramienta del fabricante.
- **Limpieza**: categorías de archivos temporales/cachés. Analiza primero y
  **el usuario decide** qué borrar (puede desmarcar archivos sueltos).
- **Espacio**: analizador tipo WizTree/TreeSize (árbol de carpetas, treemap,
  archivos más grandes, tipos de archivo), borrado con Papelera opcional.
- **Seguridad**: detecta mineros ocultos (CPU/GPU por proceso, pools,
  monederos, procesos que imitan a Windows o inyectados en herramientas
  .NET), persistencia (Run, carpeta Inicio, tareas, servicios, WMI,
  Winlogon/IFEO/AppInit), antivirus (estado, firmas, detecciones,
  exclusiones), archivo hosts y qué está llenando el disco. El usuario elige
  qué eliminar; todo va a una **cuarentena restaurable**. Lanza análisis de
  Microsoft Defender (rápido, completo, sin conexión).
- **Optimización**: plan de energía, Modo juego, Game DVR, HAGS,
  aceleración del ratón, hibernación, Sensor de almacenamiento, programas de
  inicio.
- **Mantenimiento**: TRIM/optimizar, chkdsk /scan, SFC, DISM, limpieza de
  WinSxS, vaciar DNS, con salida en vivo.

Interfaz en **español**. Nombre: **NexFix**.

## Stack

- **Tauri 2** (Rust + WebView2) → binario pequeño y poco consumo.
- **Backend Rust** (`src-tauri/`): `windows-sys` (Win32 FFI), `wmi`,
  `sysinfo` (sin features por defecto: `system`, `disk`), `winreg`, `rayon`,
  `trash`, `glob`, `parking_lot`.
- **Frontend**: Svelte 5 (runes) + TypeScript + Vite, CSS propio (sin
  frameworks de UI). TypeScript fijado en ^6 (svelte-check no admite 7).
- Gestor de paquetes: **pnpm**. Toolchain: Rust stable MSVC (instalado con
  `winget install Rustlang.Rustup`), VS 2022 C++ y WebView2 ya presentes.

## Comandos

```bash
pnpm install
pnpm tauri dev                 # desarrollo con recarga (o `cargo tauri dev`)
cd src-tauri && cargo run      # también vale: arranca Vite solo si no está en marcha (devserver.rs)
pnpm tauri build               # instalador NSIS en src-tauri/target/release/bundle/nsis
pnpm check                     # svelte-check / tipos
cd src-tauri && cargo check    # solo backend
cd src-tauri && cargo run --release --example probe -- <modo> [arg]
```

`probe` es una sonda de diagnóstico sin interfaz (`src-tauri/examples/probe.rs`
→ `nexfix_lib::probe_json`). Modos: `system`, `storage`, `tweaks`, `startup`,
`live`, `junk`, `security`, `quarantine`, `scan <ruta>`, `walk <ruta>`,
`mft <letra>`, `mftdiag`, `mftdiag2`.

Desde Linux (sesiones en la nube) se puede comprobar el backend con
`rustup target add x86_64-pc-windows-msvc` y
`cargo check --target x86_64-pc-windows-msvc` (no enlaza ni ejecuta). Para probar como admin desde una terminal normal:
`Start-Process cmd -Verb RunAs -ArgumentList '/c probe.exe storage > out.txt'`.

## Git

- Commits y PR **sin marca de Claude**: nada de `Co-Authored-By`, enlaces de
  sesión ni "Generated with Claude Code" (lo pidió el usuario).
- Autor y committer: `FaberGomezDev <faber_gomez@outlook.com>`, como los
  commits del usuario (configúralo con `git config user.name/user.email` en
  el clon si el entorno trae otra identidad).

## Estructura

```
src-tauri/src/
  lib.rs          estado (AppState), comandos Tauri, probe_json
  util.rs         procesos ocultos, decodificación de consola (UTF-16/OEM), rutas largas
  fswalk.rs       enumeración rápida: FindFirstFileExW (Basic + LARGE_FETCH)
  analyzer.rs     analizador de espacio (árbol en arena), borrado y safety
  mft.rs          escaneo de volumen completo leyendo la MFT (admin) — ver decisiones
  cleaner.rs      categorías de limpieza, escaneo y borrado
  storage.rs      discos físicos (WMI Storage), volúmenes, TRIM, archivos de sistema
  nvme.rs         log SMART/Health NVMe vía IOCTL_STORAGE_QUERY_PROPERTY (admin)
  system.rs       inventario de hardware (WMI), pantallas, estadísticas en vivo
  tweaks.rs       ajustes gaming (registro / powercfg / SystemParametersInfo)
  startup.rs      programas de inicio (Run + carpeta Inicio, StartupApproved)
  maintenance.rs  tareas de Windows con salida en streaming
  elevation.rs    detección de admin y "reiniciar como administrador"
  safety.rs       rutas protegidas (nunca se borran), objetivos de seguridad, dueño admin
  security.rs     análisis de seguridad: procesos/GPU, persistencia, antivirus, hosts, disco
  quarantine.rs   remediación (cerrar, cuarentena, quitar persistencia), restaurar, ignorados
  sign.rs         firma Authenticode (WinVerifyTrust) y recursos de versión
  gpu.rs          uso de GPU y VRAM por proceso (contadores PDH "GPU Engine")
  devserver.rs    solo `cfg(dev)`: arranca Vite si `cargo run` lo necesita
  wmiq.rs         consultas WMI sin tipos + getters tolerantes
src/              frontend Svelte (vistas en src/lib/views)
docs/             arquitectura, decisiones y bitácora
```

## Reglas del proyecto (no romper)

1. **Nada se borra sin que el usuario lo elija.** Escanear solo mide.
2. Carpetas personales (Descargas) en modo *explícito*: solo se borran los
   archivos marcados uno a uno, y van a la Papelera.
3. `safety::check_deletable` protege Windows, raíces de unidad, raíces de
   Program Files/ProgramData/Usuarios/carpetas conocidas y archivos de sistema.
4. Los comandos de mantenimiento están **fijos en Rust**; la UI solo envía un
   id de tarea y una letra de unidad validada.
5. WMI/COM nunca en el hilo de la UI: `spawn_blocking`. La Papelera (`trash`)
   siempre en un **hilo nuevo** (inicializa COM STA y entra en pánico si el
   hilo ya tiene otro modelo COM).
6. La app arranca sin admin; lo que necesita admin lo indica y ofrece
   "Reiniciar como administrador".
7. Toda la UI en español; textos claros sobre el riesgo de cada acción.
8. **Seguridad**: analizar nunca cambia nada. Cada hallazgo explica sus
   motivos y el plan exacto de lo que hará "Eliminar"; solo se preseleccionan
   los críticos. Todo cambio deja copia en la cuarentena (salvo WMI). Nunca se
   tocan archivos de la carpeta de Windows (salvo `Windows\Temp`) ni firmados
   por Microsoft, ni se cierran procesos críticos (csrss, lsass, svchost…).
9. Restaurar como admin solo usa copias del almacén de administrador
   (`%ProgramData%\NexFix\Cuarentena`, dueño Administradores); el de usuario
   (`%LOCALAPPDATA%`) solo restaura archivos dentro del perfil y valores HKCU.

## Estado actual (2026-10-06)

- Backend y frontend completos (8 vistas). El usuario ya ejecuta la app con
  `pnpm tauri dev` en su PC.
- **Nuevo (sesión 2)**: vista Seguridad + módulos `security`, `quarantine`,
  `sign`, `gpu`; GPU en vivo en Resumen; tareas de Defender y "Desactivar
  Windows Sandbox" en Mantenimiento. Compila (`cargo check`/`clippy` para
  Windows, `pnpm check`, `pnpm build`) y la vista se revisó con datos
  simulados, pero **aún no se ha ejecutado en Windows**.
- Lectura MFT: bloqueada en este PC (ERROR_NOT_SUPPORTED en lecturas raw y
  FSCTL_QUERY_FILE_LAYOUT); se usa el recorrido paralelo (≈11 s para C:
  completo, 2,9 M archivos). En investigación.

## Próximos pasos

1. Probar Seguridad en el PC del usuario: `probe security` normal y como
   admin; anotar tiempos y falsos positivos en la bitácora y ajustar pesos
   (`security.rs`, constantes y `score_process`).
2. Probar la remediación con un caso inofensivo (p. ej. una entrada Run de
   prueba) y restaurar desde la cuarentena, normal y como admin.
3. `pnpm tauri build` y probar el instalador.
4. Cerrar la decisión sobre `mft.rs` (mantener como estrategia oportunista o
   retirarlo si no se puede validar).
