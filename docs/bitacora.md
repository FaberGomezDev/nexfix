# Bitácora

Registro cronológico de lo hecho, mediciones y hallazgos. Lo más reciente
abajo.

## 2026-10-05 — Sesión 1

### Entorno
- Windows 11 Pro build 26300, Ryzen 7 7700X, 32 GB DDR5, RTX 4060 + iGPU
  Radeon, placa ASUS PRIME B650-PLUS (BIOS 3040 del 2024-09-12).
- Disco: Corsair MP600 ELITE 2 TB NVMe (M.2), un único volumen C: NTFS.
- Instalado Rust 1.99 (stable-msvc) con winget. Node 22, pnpm 9.

### Hecho
- Estructura Tauri 2 + Svelte 5 creada a mano (sin plantilla interactiva).
- Backend Rust completo (todos los módulos de `src-tauri/src`).
- Icono generado con `pnpm tauri icon src-tauri/icons/logo.svg`.
- Sonda `examples/probe.rs` para verificar módulos sin interfaz.

### Mediciones (sonda en release)
| Prueba | Resultado |
|---|---|
| `system` | 110 ms; RAM Corsair CMH32GX5M2B6400C36 (kit 6400) a 6000 MT/s; monitor a 120 Hz con máximo 240 Hz |
| `storage` (sin admin) | 630 ms; TRIM activo; pagefile 29 GB, hiberfil 13,4 GB; 427 GB libres de 1,82 TB |
| `storage` (admin) | SMART NVMe OK: 44 °C, 2 % usado, 42 TB escritos, 4 811 h, 50 apagados inseguros, 0 errores |
| `junk` | 4,1 s → **1,5 s** tras paralelizar dentro de cada categoría |
| Hallazgo limpieza | caché DX de NVIDIA: **32 GB** (`%LOCALAPPDATA%\NVIDIA\DXCache`); temporales de usuario 4,5 GB; npm 7,8 GB; pip 4,3 GB |
| `scan C:\` (frío) | 105 s, 3,3 M archivos, 1,14 M carpetas |
| `scan C:\` (caliente) | 61 s; 48 s en `ProgramData\Microsoft\Windows\Containers\Layers` |
| `walk C:\` con D4 | **11,5 s**, 2,9 M archivos, 743 k carpetas, 1,60 TB (usado real 1,57 TB) |
| MFT raw (admin) | `ReadFile` en `\\.\C:` → ERROR_NOT_SUPPORTED (50) |
| `FSCTL_GET_NTFS_VOLUME_DATA` | OK: clúster 4 KB, registro 1 KB, MFT 4,5 GB |
| `FSCTL_QUERY_FILE_LAYOUT` | ERROR_NOT_SUPPORTED (50) |

### Recomendaciones detectadas para este PC (para la vista Resumen)
- Monitor a 120 Hz pudiendo 240 Hz.
- BIOS de 2024: buscar actualización (AGESA) en ASUS.
- Plan de energía Equilibrado (correcto en Ryzen 7000; opcional Alto rendimiento).
- Game DVR activo, aceleración del ratón activa.
- 32 GB de caché de shaders NVIDIA.
- Hibernación activa (13,4 GB) — opcional desactivar.
