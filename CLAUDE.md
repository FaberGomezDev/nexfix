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
pnpm tauri dev                 # desarrollo con recarga
pnpm tauri build               # instalador NSIS en src-tauri/target/release/bundle/nsis
pnpm check                     # svelte-check / tipos
cd src-tauri && cargo check    # solo backend
cd src-tauri && cargo run --release --example probe -- <modo> [arg]
```

`probe` es una sonda de diagnóstico sin interfaz (`src-tauri/examples/probe.rs`
→ `nexfix_lib::probe_json`). Modos: `system`, `storage`, `tweaks`, `startup`,
`live`, `junk`, `scan <ruta>`, `walk <ruta>`, `mft <letra>`, `mftdiag`,
`mftdiag2`. Para probar como admin desde una terminal normal:
`Start-Process cmd -Verb RunAs -ArgumentList '/c probe.exe storage > out.txt'`.

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
  safety.rs       rutas protegidas (nunca se borran)
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

## Estado actual (2026-10-05)

- Backend completo y probado con datos reales en el PC del usuario (ver
  [`docs/bitacora.md`](docs/bitacora.md)).
- Lectura MFT: bloqueada en este PC (ERROR_NOT_SUPPORTED en lecturas raw y
  FSCTL_QUERY_FILE_LAYOUT); se usa el recorrido paralelo (≈11 s para C:
  completo, 2,9 M archivos). En investigación.
- **Pendiente**: frontend Svelte completo, build del instalador, pruebas de
  la app final.

## Próximos pasos

1. Cerrar la decisión sobre `mft.rs` (mantener como estrategia oportunista o
   retirarlo si no se puede validar).
2. Escribir el frontend (vistas, componentes, insights).
3. `pnpm tauri build` y probar el ejecutable (normal y como admin).
