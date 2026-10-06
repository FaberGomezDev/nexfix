# Arquitectura de NexFix

## Visión general

```
┌──────────────── WebView2 (Svelte 5 + TS) ────────────────┐
│ Vistas: Resumen · Componentes · Discos · Limpieza ·      │
│   Espacio · Seguridad · Optimización · Mantenimiento     │
│ lib/api.ts → invoke()/listen()   lib/insights.ts         │
└───────────────▲──────────────────────────┬───────────────┘
                │ eventos                  │ comandos (JSON)
┌───────────────┴──────────────────────────▼───────────────┐
│ Rust (Tauri 2)  lib.rs: AppState + #[tauri::command]     │
│  system/gpu · storage/nvme · cleaner · analyzer/mft      │
│  security/sign/quarantine · tweaks · startup             │
│  maintenance · elevation · safety · devserver (dev)      │
└──────────────────────────────────────────────────────────┘
        Win32 (windows-sys) · WMI · Registro · procesos
```

## Estado compartido (`AppState`)

| Campo | Uso |
|---|---|
| `live: Mutex<Option<System>>` | `sysinfo::System` persistente para medir CPU por diferencia entre llamadas |
| `gpu: Mutex<(bool, Option<GpuQuery>)>` | consulta PDH persistente para la GPU en vivo (se intenta abrir una vez) |
| `security` | hallazgos del último análisis de seguridad, con sus pasos de corrección (no se envían a la UI) |
| `scans` | escaneos del analizador (`Arc<RwLock<Scan>>`); solo vive uno a la vez |
| `scan_progress` | contadores atómicos + flag de cancelación del escaneo en curso |
| `junk` | resultado del último escaneo de limpieza (listas de archivos por categoría) |
| `tasks` | procesos hijos de mantenimiento en ejecución (para cancelar) |

## Comandos Tauri

| Comando | Descripción |
|---|---|
| `is_admin`, `relaunch_admin` | elevación |
| `system_info`, `live_stats` | hardware y uso en vivo |
| `storage_info` | discos, volúmenes, SMART, TRIM |
| `junk_scan`, `junk_clean(ids, excluded, included)` | limpieza |
| `analyzer_start(path) → id`, `analyzer_cancel`, `analyzer_list(id,node)`, `analyzer_top_files`, `analyzer_extensions`, `analyzer_summary` | analizador |
| `delete_paths(scan_id?, paths, to_recycle)` | borrado del analizador (actualiza el árbol) |
| `reveal_in_explorer(path)` | abrir en el Explorador |
| `maintenance_tasks`, `task_run(id, drive?)`, `task_cancel` | mantenimiento |
| `tweaks_get`, `tweak_set(name, enabled)`, `power_plan_set`, `power_plan_add_ultimate` | optimización |
| `startup_list`, `startup_set(id, enabled)` | programas de inicio |
| `security_scan` | análisis de seguridad completo (~2-5 s) |
| `security_fix(ids)` | aplica el plan de los hallazgos elegidos |
| `security_ignore(key, ignored)` | lista de "de confianza" (`%LOCALAPPDATA%\NexFix\seguridad.json`) |
| `quarantine_list`, `quarantine_restore(id)`, `quarantine_delete(id)` | cuarentena |
| `defender_scan_file(path)` | `MpCmdRun -Scan -ScanType 3 -File … -DisableRemediation` |
| `open_windows_security` | abre Seguridad de Windows (`windowsdefender://threat/`) |

## Eventos (backend → UI)

| Evento | Payload |
|---|---|
| `analyzer://progress` | `{id, files, dirs, bytes, errors, current}` cada ~140 ms |
| `analyzer://done` | `{id, ok, error?, summary?}` |
| `cleaner://progress` | `{category, done, total, freed}` |
| `task://output` | `{task, line, replace}` (`replace` = línea terminada en `\r`, barra de progreso) |
| `task://done` | `{task, code, success, cancelled}` |

## Analizador de espacio

- **Recorrido (`analyzer::walk_scan`)**: recursión paralela con un pool
  `rayon` propio (2×núcleos, pila 8 MB). Cada carpeta se lista una vez con
  `FindFirstFileExW(FindExInfoBasic, FIND_FIRST_EX_LARGE_FETCH)`. No sigue
  uniones/symlinks (reparse *name surrogate*). Omite
  `ProgramData\Microsoft\Windows\Containers\{Layers,BaseImages}` (capas
  virtuales de contenedores; ver decisiones).
- **Árbol**: solo carpetas, en un *arena* (`Vec<Node>`) con hijos ordenados
  por tamaño. Los archivos se agregan (tamaño/cantidad propios); al abrir una
  carpeta en la UI se vuelven a listar sus archivos directos del disco.
- **Top 300 archivos**: min-heap con umbral atómico (solo se bloquea cuando
  un archivo supera el umbral).
- **Extensiones**: mapa local por carpeta fusionado en un mapa global.
- **Borrado**: actualiza el árbol restando a los ancestros; si un borrado de
  carpeta falla a medias se re-mide lo que queda.
- **MFT (`mft.rs`)**: si el destino es la raíz de un volumen NTFS y hay admin
  se intenta (1) lectura directa de la MFT, (2) `FSCTL_QUERY_FILE_LAYOUT`;
  si ambas fallan, recorrido normal.

## Limpieza

Categorías definidas en `cleaner::categories()` con: riesgo
(`safe/moderate/caution`), seleccionada por defecto, requiere admin, edad
mínima (temporales: 24 h), enviar a Papelera, modo explícito. Los objetivos
son `(carpeta base, sufijo glob)`; la base se escapa con `glob::Pattern::escape`.
El escaneo es paralelo por categoría y dentro de cada carpeta. El borrado es
paralelo (`rayon`), quita solo-lectura si hace falta, salta archivos en uso y
después elimina subcarpetas vacías (nunca la raíz de la categoría).

## SMART NVMe

`IOCTL_STORAGE_QUERY_PROPERTY` con `StorageDeviceProtocolSpecificProperty`,
`ProtocolTypeNvme`, `NVMeDataTypeLogPage`, página 0x02 (512 bytes). Requiere
abrir `\\.\PhysicalDriveN` con lectura/escritura → admin. Las unidades de
datos son miles de sectores de 512 B. Para SATA se usa
`MSFT_StorageReliabilityCounter` (admin).

## Seguridad (`security.rs`, `quarantine.rs`)

El análisis combina señales explicables en una puntuación por hallazgo
(`Score { points, reasons }`). Niveles: ≥ 80 crítico, ≥ 50 alto, ≥ 30
revisar; por debajo no se muestra (salvo entradas de inicio rotas, "info").

1. **Procesos** (`sample_processes`): dos lecturas de `sysinfo` separadas
   1,6 s (CPU, memoria, escritura en disco, ruta, línea de comandos) más los
   contadores PDH `\GPU Engine(*)\Utilization Percentage` y
   `\GPU Process Memory(*)\Dedicated Usage` (`gpu.rs`; uso = motor más
   ocupado, como el Administrador de tareas; "cómputo" = motores
   Compute/CUDA). Se agrupan por ejecutable. `EnumWindows` marca los que
   tienen ventana visible.
2. **Señales de archivo** (`analyze_file`): nombre de minero conocido o
   carpeta con ese nombre, ubicación (`Places::classify`: Windows, Program
   Files, AppData/ProgramData, sospechosa = Temp/Public/Papelera/raíz/
   subcarpetas raras de Windows), nombre de proceso de Windows fuera de
   Windows, nombres parecidos (svch0st…), atributo oculto/sistema.
3. **Señales de línea de comandos** (`analyze_command`): `stratum+tcp://`,
   dominios de pools, opciones de XMRig y similares, monederos (Monero/ETH),
   PowerShell ofuscado o que descarga, LOLBins (mshta, regsvr32, rundll32,
   certutil, bitsadmin), scripts en carpetas de usuario.
4. **Inyección**: herramientas .NET (AddInProcess, RegAsm, InstallUtil…)
   ocupadas y sin ventana; notepad/explorer/conhost usando GPU en cómputo.
5. **Recursos** (solo procesos sin ventana; para binarios de Windows o rutas
   desconocidas solo si ya hay otra señal): GPU ≥ 25 %, cómputo, VRAM ≥ 1,5
   GB, CPU ≥ 20/50 %, escritura ≥ 30 MB/s.
6. **Firma** (`sign.rs`, solo candidatos, en paralelo y con caché):
   `WinVerifyTrust` sin red + nombre del firmante; firma válida resta 35, sin
   firma suma 5-15, firma inválida suma 25. Sin firma válida se leen los
   recursos de versión (XMRig renombrado, "miner" en la descripción).
7. **Persistencia**: Run/RunOnce/Policies (reutiliza `startup.rs`, destino de
   los `.lnk` leído del binario), Winlogon Shell/Userinit, IFEO `Debugger`,
   AppInit_DLLs, servicios y drivers (registro; `ServiceDll` de svchost),
   tareas programadas (XML de `System32\Tasks`, admin) y consumidores WMI
   (`root\subscription`, admin).
8. **Antivirus**: `SecurityCenter2\AntiVirusProduct` (productState),
   `MSFT_MpComputerStatus`, `MSFT_MpThreat(Detection)`, exclusiones de
   Defender del registro (admin) con su riesgo; archivo hosts que redirige
   dominios de antivirus/Windows Update.
9. **Disco**: recorrido paralelo de Temp, AppData (Local/Roaming/LocalLow),
   ProgramData, Public, Windows\Logs y raíz de C:; agrupa lo escrito en 7 días
   por carpeta, lista archivos grandes con explicación conocida (`NOTES`) y
   detecta el fallo de los CAB en `Windows\Temp`, logs desbocados y un índice
   de búsqueda enorme.

**Remediación** (`FixStep`): `Kill` (verifica que el PID sigue siendo el
mismo ejecutable y repite para parejas "watchdog"), `Quarantine`,
`DeleteRegValue`/`SetRegValue`, `DeleteTask` (schtasks), `DisableService`
(Start=4 + `sc stop`), `RemoveWmi` y `RemoveExclusion` (PowerShell con el
valor en la variable de entorno `NEXFIX_ARG`, nunca dentro del script),
`CommentHosts`, `DeleteFiles`. Cada paso guarda copia en el índice
(`indice.json`) del almacén: administrador (`%ProgramData%`, se confía solo en
archivos cuyo dueño es Administradores/SYSTEM; los archivos movidos se
`icacls /reset` + `/setowner`) o usuario (`%LOCALAPPDATA%`). Si un archivo
sigue bloqueado y hay admin, se programa su borrado al reiniciar
(`MOVEFILE_DELAY_UNTIL_REBOOT`). Las rutas se resuelven con `canonicalize`
para que una unión creada por malware no redirija la operación a Windows.

## Mantenimiento

Procesos ocultos (`CREATE_NO_WINDOW`) con stdout/stderr leídos por hilos que
detectan UTF-16 (sfc) u OEM/UTF-8 y separan líneas por `\r` y `\n`.
Incluye Microsoft Defender (`MpCmdRun` más reciente de
`ProgramData\Microsoft\Windows Defender\Platform`: rápido, completo,
actualizar firmas; `Start-MpWDOScan` para el análisis sin conexión) y
"Desactivar Windows Sandbox" (`DISM /Disable-Feature
/FeatureName:Containers-DisposableClientVM`). La UI pide confirmación para
las tareas que reinician o quitan características.

## Desarrollo: `cargo run`

En compilación de desarrollo (`cfg(dev)`) la ventana carga `devUrl`
(`http://localhost:1420`). `devserver::ensure` comprueba el puerto; si nadie
escucha, lanza `pnpm dev` (o `pnpm install && pnpm dev`) desde la raíz del
proyecto, espera a que responda y lo cierra (`taskkill /T`) al salir. Si no
puede, muestra un mensaje explicando `pnpm tauri dev` en vez de la página de
error de WebView2.
