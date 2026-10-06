# Arquitectura de NexFix

## Visión general

```
┌──────────────── WebView2 (Svelte 5 + TS) ────────────────┐
│ Vistas: Resumen · Componentes · Discos · Limpieza ·      │
│         Espacio · Optimización · Mantenimiento           │
│ lib/api.ts → invoke()/listen()   lib/insights.ts         │
└───────────────▲──────────────────────────┬───────────────┘
                │ eventos                  │ comandos (JSON)
┌───────────────┴──────────────────────────▼───────────────┐
│ Rust (Tauri 2)  lib.rs: AppState + #[tauri::command]     │
│  system · storage/nvme · cleaner · analyzer/mft/fswalk   │
│  tweaks · startup · maintenance · elevation · safety     │
└──────────────────────────────────────────────────────────┘
        Win32 (windows-sys) · WMI · Registro · procesos
```

## Estado compartido (`AppState`)

| Campo | Uso |
|---|---|
| `live: Mutex<Option<System>>` | `sysinfo::System` persistente para medir CPU por diferencia entre llamadas |
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

## Mantenimiento

Procesos ocultos (`CREATE_NO_WINDOW`) con stdout/stderr leídos por hilos que
detectan UTF-16 (sfc) u OEM/UTF-8 y separan líneas por `\r` y `\n`.
