# NexFix

**Análisis, limpieza, seguridad y mantenimiento para PC gamer con Windows.**

NexFix es una aplicación de escritorio para Windows 10/11 pensada para quien
juega y quiere que su PC rinda como debe sin tener que conocer cada rincón de
Windows. Revisa el hardware, los discos, el espacio, la configuración y la
seguridad del equipo, explica en español qué encuentra y por qué importa, y
propone soluciones concretas. **Nunca borra ni cambia nada sin que tú lo
elijas.**

## Para qué está pensado

- Descubrir por qué el PC no rinde lo que debería: RAM sin su perfil
  EXPO/XMP, monitor a menos hercios de los que admite, cable conectado a la
  gráfica integrada, drivers antiguos, plan de energía de ahorro…
- Cuidar los SSD y M.2: temperatura, desgaste, TB escritos, TRIM.
- Recuperar espacio de forma segura y saber qué está ocupando el disco.
- Detectar mineros de criptomonedas ocultos que usan la gráfica o la CPU, y
  programas que llenan el disco sin motivo.
- Ejecutar las herramientas de mantenimiento de Windows sin pelearse con la
  consola.

## Qué hace

| Vista | Qué incluye |
|---|---|
| **Resumen** | Puntuación de salud del PC, recomendaciones accionables, uso en vivo de CPU, RAM y GPU, y los procesos que más consumen. |
| **Componentes** | CPU, módulos de RAM (velocidad real frente a la nominal), GPU (VRAM real, driver), placa base y BIOS, monitores (Hz actuales frente a máximos). |
| **Discos y M.2** | Discos físicos y bus (NVMe/SATA), salud y SMART completo de NVMe (temperatura, desgaste, datos escritos, horas, errores), TRIM, archivo de paginación e hibernación, herramienta del fabricante. |
| **Limpieza** | Temporales, cachés de Windows, navegadores, launchers y sombreadores de la GPU. Primero analiza y luego decides qué categorías o archivos borrar. |
| **Espacio** | Analizador tipo WizTree/TreeSize: árbol de carpetas, mapa de bloques, archivos más grandes y tipos de archivo, con borrado opcional a la Papelera. |
| **Seguridad** | Detecta mineros ocultos (uso de GPU y CPU por proceso, pools, monederos, procesos que imitan a Windows), inicio automático sospechoso (registro, tareas, servicios, WMI), el estado del antivirus y sus exclusiones, un archivo `hosts` manipulado y qué está llenando el disco. Lo que elijas eliminar va a una cuarentena desde la que puedes restaurarlo. |
| **Optimización** | Plan de energía, Modo juego, grabación de Xbox Game Bar, HAGS, aceleración del ratón, hibernación, Sensor de almacenamiento y programas de inicio. |
| **Mantenimiento** | TRIM y optimización de unidades, `chkdsk /scan`, SFC, DISM, limpieza de WinSxS, vaciar la caché DNS y análisis de Microsoft Defender, con la salida en vivo. |

## Principios

- **Analizar solo mide.** Nada se borra, se cierra o se cambia hasta que lo
  eliges y lo confirmas.
- **Todo se explica.** Cada recomendación o amenaza dice qué ha visto NexFix y
  qué hará exactamente si la aceptas.
- **Reversible siempre que se puede.** Los ajustes se pueden revertir, tus
  descargas van a la Papelera y lo que se elimina desde Seguridad queda en
  cuarentena con copia de seguridad.
- **Zonas protegidas.** La carpeta de Windows, las raíces de las unidades, las
  carpetas de usuario y de programas, y los archivos firmados por Microsoft
  nunca se borran.
- **Sin administrador por defecto.** La app arranca en modo estándar y te
  avisa cuando algo necesita permisos (SMART completo, archivos del sistema,
  tareas de mantenimiento, análisis de seguridad completo), con un botón para
  reiniciarla como administrador.

> NexFix no sustituye a un antivirus: la vista Seguridad busca comportamientos
> sospechosos y se apoya en Microsoft Defender para el análisis por firmas.

## Requisitos

- Windows 10 u 11 (64 bits) con WebView2 (incluido en Windows 11).

## Desarrollo

Necesitas [Rust](https://rustup.rs) (toolchain MSVC), Node.js, pnpm y las
herramientas de compilación de C++ de Visual Studio.

```bash
pnpm install
pnpm tauri dev        # app con recarga en caliente
pnpm tauri build      # instalador en src-tauri/target/release/bundle/nsis
pnpm check            # comprobación de tipos del frontend
```

`cd src-tauri && cargo run` también funciona: si el servidor de la interfaz no
está en marcha, la app lo arranca sola.

## Tecnología

- [Tauri 2](https://tauri.app): núcleo en Rust y WebView2, ejecutable pequeño
  y bajo consumo.
- Backend en Rust con acceso directo a Win32, WMI y el registro.
- Interfaz en Svelte 5 + TypeScript con CSS propio.

La estructura del código, las decisiones de diseño y la bitácora están en
[`docs/`](docs/).
