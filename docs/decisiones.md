# Registro de decisiones

Formato: contexto → decisión → consecuencias. Añadir nuevas al final.

## D1 · Tauri 2 + Rust + Svelte 5 (2026-10-05)

- **Contexto**: el usuario pidió "Rust o lo mejor que haya", con interfaz
  óptima y eficiente.
- **Decisión**: Tauri 2 (núcleo Rust, UI en WebView2) con Svelte 5 + TS.
- **Consecuencias**: binario de pocos MB, bajo consumo de RAM, acceso nativo a
  Win32. Electron descartado por peso; egui/Slint descartados por esfuerzo de
  UI rica (treemap, tablas, gráficos).

## D2 · `windows-sys` en lugar de `windows` (2026-10-05)

- FFI crudo, compila más rápido. Las estructuras que dependen de la versión
  del SDK (consultas NVMe, extents de volumen) se definen a mano con
  `#[repr(C)]` para no depender de nombres de campos.

## D3 · Enumeración con `FindFirstFileExW` (2026-10-05)

- `FindExInfoBasic` + `FIND_FIRST_EX_LARGE_FETCH` es más rápido que
  `std::fs::read_dir` y da tamaño, atributos, fecha y etiqueta de reparse en
  una sola llamada. Rutas con prefijo `\\?\` para superar MAX_PATH.

## D4 · Omitir capas virtuales de contenedores (2026-10-05)

- **Contexto**: `C:\ProgramData\Microsoft\Windows\Containers\Layers`
  (Windows Sandbox / contenedores) tenía 395 000 carpetas y tardaba **49 s**
  de un total de 61 s; además son enlaces duros a archivos ya contados
  (inflaba el total ~110 GB).
- **Decisión**: el recorrido no entra en `Containers\Layers` ni
  `Containers\BaseImages`; el nodo se marca `skipped`.
- **Consecuencia**: escaneo de C: completo en ~11 s. La UI debe explicar que
  esa carpeta se omite.

## D5 · Lectura de la MFT como estrategia oportunista (2026-10-05, abierta)

- **Contexto**: leer la MFT (como WizTree) daría escaneos de segundos y
  contaría los enlaces duros una sola vez.
- **Hallazgo**: en el PC del usuario (Windows 11 build 26300, con Riot
  Vanguard, FACEIT, Avast/McAfee instalados) las lecturas raw de `\\.\C:` y
  `FSCTL_QUERY_FILE_LAYOUT` devuelven `ERROR_NOT_SUPPORTED (50)` incluso como
  admin; `FSCTL_GET_NTFS_VOLUME_DATA` sí funciona.
- **Decisión**: mantener `mft.rs` como primer intento solo para raíces de
  volumen con admin; si falla, recorrido normal (el fallo es inmediato,
  < 5 ms). Orden: lectura raw → `FSCTL_QUERY_FILE_LAYOUT` → recorrido.
- **Validación**: `FSCTL_GET_NTFS_FILE_RECORD` sí funciona en este PC
  (devuelve registros con fixups ya aplicados, ~20 µs/registro: demasiado
  lento para producción, 86 s para 4,4 M). Con él se validó el parser
  (`probe mftdiag2`): árbol, top de archivos y extensiones coherentes con el
  recorrido. Se corrigió un fallo: nombres en registros de extensión leídos
  antes que su registro base (se resuelven al final con `Parsed::finalize`).
- `FSCTL_ENUM_USN_DATA` también funciona, pero no da tamaños.

## D6 · Descargas en modo explícito (2026-10-05)

- Con "excluir lo desmarcado" se borrarían archivos que el usuario no ve en
  la lista (solo se muestran los 400 mayores). Para carpetas personales se
  invierte la lógica: solo se borra lo marcado y va a la Papelera.

## D7 · Papelera en hilo nuevo (2026-10-05)

- El crate `trash` inicializa COM en STA por hilo y hace `panic!` si el hilo
  ya tiene otro modelo. Todo uso de `trash` y `SHEmptyRecycleBinW` va en un
  `std::thread` recién creado (`fresh_thread` en `lib.rs`).
- Se quitó `panic = "abort"` del perfil release para no tumbar la app ante un
  pánico en un hilo de trabajo.

## D8 · Cachés de shaders no seleccionadas por defecto (2026-10-05)

- Borrarlas es seguro pero provoca tirones en los juegos mientras se
  regeneran. Se marcan como riesgo "moderado" y se recomiendan solo tras
  actualizar drivers o ante problemas gráficos. (En el PC del usuario la
  caché DX de NVIDIA ocupa 32 GB.)

## D9 · TypeScript 6 (2026-10-05)

- `svelte-check` 4.7 exige TS ^5 || ^6; TS 7 rompe la comprobación.

## D10 · Seguridad por heurística explicable, no por firmas (2026-10-06)

- **Contexto**: el usuario pidió detectar y eliminar malware de minería que
  consuma GPU/CPU y malware que llene el disco.
- **Decisión**: NexFix no es un antivirus (no tiene base de firmas). Detecta
  comportamientos y rasgos típicos (pools/monederos en la línea de comandos,
  procesos que imitan a Windows, inyección en herramientas .NET, uso de GPU
  en cómputo sin ventana, persistencia rara, exclusiones del antivirus,
  hosts manipulado) con una puntuación cuyos motivos se muestran al usuario.
  Para la detección por firmas se apoya en Microsoft Defender (análisis
  rápido/completo/sin conexión y análisis de un archivo concreto).
- **Consecuencias**: puede haber falsos positivos (sobre todo herramientas
  sin firma en segundo plano): por eso la firma válida resta puntos, solo se
  preseleccionan los críticos, existe "Es de confianza, ignorar" y todo se
  puede restaurar. Los pesos están en `security.rs` y se deben ajustar con
  datos reales del PC del usuario.

## D11 · Cuarentena en dos almacenes con comprobación de dueño (2026-10-06)

- **Contexto**: restaurar como administrador a partir de datos que un proceso
  del usuario puede escribir permitiría a un malware sin privilegios usar
  NexFix para elevarse (p. ej. una tarea "restaurada" como SYSTEM).
- **Decisión**: con admin se usa `%ProgramData%\NexFix\Cuarentena` y solo se
  confía en archivos cuyo dueño es Administradores/SYSTEM (los archivos
  movidos se pasan a ese dueño con `icacls`); sin admin,
  `%LOCALAPPDATA%\NexFix\Cuarentena`, que solo restaura archivos dentro del
  perfil y valores HKCU. Las rutas se canonicalizan (uniones) y el registro
  solo se restaura en las claves que NexFix modifica.
- **Consecuencias**: lo puesto en cuarentena como admin solo se restaura
  como admin. Las suscripciones WMI eliminadas no se pueden restaurar.

## D12 · `cargo run` arranca Vite (2026-10-06)

- **Contexto**: con `cargo run` la app compila en modo desarrollo y carga
  `http://localhost:1420`; sin `pnpm dev` WebView2 mostraba "localhost
  rechazó la conexión" (le pasó al usuario).
- **Decisión**: `devserver.rs` (solo `cfg(dev)`) arranca `pnpm dev` si el
  puerto no responde y lo cierra al salir; si no puede, explica qué ejecutar.
  Lo recomendado sigue siendo `pnpm tauri dev` / `cargo tauri dev`.

## D13 · Vite 8 minifica con Oxc (2026-10-06)

- `minify: "esbuild"` exige instalar esbuild aparte en Vite 8 y rompía
  `pnpm build` (y por tanto `pnpm tauri build`). Se usa `minify: "oxc"`.

## D14 · Capas de contenedores: nunca se borran a mano (2026-10-06)

- **Contexto**: el usuario vio que `ProgramData\Microsoft\Windows\Containers\Layers`
  "ocupa mucho" y preguntó cómo borrarlo.
- **Decisión**: son capas de Windows Sandbox/contenedores, casi todo enlaces
  duros a archivos de Windows (ocupan mucho menos de lo que aparentan, ver
  D4). `safety::check_deletable` impide borrarlas desde Espacio; Espacio
  explica qué son y Mantenimiento ofrece "Desactivar Windows Sandbox"
  (DISM), que es la forma soportada de que Windows deje de mantenerlas.
