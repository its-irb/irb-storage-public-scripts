# Plan: montar cada servidor MinIO entero (un volumen por perfil)

Rama: `feature/mount-por-perfil` (desde `develop`). Última actualización: 2026-11-23.

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Pruebas manuales con rclone (Windows y macOS) | **Hecha** |
| 1 | `refactor(mount)`: separar procesos y carpeta de montaje, sin cambiar el comportamiento | **Hecha** (tests en verde; probada a mano en macOS) |
| 2 | `feat(mount)`: API por perfil, limpieza de los montajes por bucket y opciones de rendimiento | **Implementada** junto con la 3 |
| 3 | `feat(mount)`: pantalla de servidores con tarjetas, flujo en `main.py`, borrar lo de buckets y documentación de usuario | **Implementada** (tests en verde y prueba real del backend en macOS; pendiente la prueba manual de la app, Windows y el commit) |
| 4 | `docs(mount)`: revisión final de la documentación con `docs-update` | Pendiente |

La documentación técnica (`docs/agent/`, `docs/development/`) se actualiza en el commit de cada fase; la de
usuario, en la fase 3, que es cuando cambia lo que ve el usuario. Las fases 2 y 3 se hicieron seguidas, en un solo
cambio (decisión del 2026-11-23): lo de "la fase 2 solo añade" ya no aplica. Ver "Fases 2 y 3 — lo implementado".

## Objetivo

1. **Mismo modelo en Windows, macOS y Linux**: cada servidor (perfil de rclone: `minio`, `minio-archive`,
   `irbminio`) se monta entero, con sus buckets como carpetas de primer nivel. Un volumen por perfil.
2. **Rutas que empiezan en una raíz en Windows**: el montaje en carpeta de WinFsp (`C:\rclone-mounts\…`) hace que
   programas Java (visores como QuPath) no abran los ficheros. Con letra de unidad (`X:\<bucket>\…`) sí abren.
3. **Pantalla más simple**: desaparece la lista de buckets; se monta desde la pantalla de servidores.

## Fase 0 — resultados (rclone 1.72.1)

- **Windows**: `rclone mount minio: X: --read-only --links --vfs-cache-mode full` funciona; los buckets salen como
  carpetas de `X:\` y el visor Java abre los ficheros.
- **macOS (fuse-t)**: `rclone mount minio: ~/rclone-mounts/minio --read-only --links --allow-non-empty
  --vfs-cache-mode full` funciona. Java ya funcionaba antes con rutas de carpeta.
- **`--volname`**: sin él, rclone llama al volumen como el perfil (`minio`)… salvo que una opción de backend cambie
  la configuración del perfil: con `--s3-no-head-object` (opciones de rendimiento) rclone le añade un sufijo y en
  Windows la unidad salía como `minio{EVwtF}` (2026-11-23). Por eso el comando lleva `--volname <perfil>`.
- **`/Volumes` descartado**: es de `root`; montar ahí exige `sudo` y rclone no crea la carpeta. Se monta en
  `~/rclone-mounts/<perfil>`.
- **El Finder enseña `fuse-t`**: es el nombre de máquina del NFS local de fuse-t (`127.0.0.1 fuse-t` en
  `/etc/hosts`). No cambia con `--volname` ni con `-o backend=smb`. Se acepta: es cosmético.
- **Listados lentos**: un `ls -la` de una carpeta con muchas imágenes tardó más de 2 minutos, medido con una
  búsqueda `rclone lsf -R` en paralelo. Repetir la medida sin carga en la fase 3.
- **Opciones de rendimiento** (probadas a mano, 2026-11-23): con estas opciones el montaje va mejor que con las
  actuales, y se usarán en todos los montajes de MinIO:

  ```text
  --vfs-cache-mode full
  --vfs-read-chunk-size 32M --vfs-read-chunk-size-limit 32M
  --buffer-size 32M
  --s3-no-head-object
  --dir-cache-time 12h
  --vfs-cache-max-size 10G
  ```

## Decisiones

| Tema | Decisión |
|---|---|
| Qué se monta | El perfil entero (`<perfil>:`), siempre en solo lectura. No se puede montar un solo bucket ni una carpeta. |
| Dónde | Windows: primera letra libre desde `D:`. macOS y Linux: `~/rclone-mounts/<perfil>` (cambiar el nombre de la carpeta base queda para el futuro). |
| Servidores | Las tres tarjetas de `MINIO_SERVERS`. Un servidor nuevo en `constants.py` sale sin tocar la vista. |
| Montar | Botón **Mount** de la tarjeta y doble clic en la tarjeta. Si ya está montado, se abre la carpeta. |
| Desmontar | Botón **Unmount** en cada tarjeta. Al cerrar la app se desmonta todo (`desmontar_todos_los_mounts_s3`). |
| Credenciales | Se comprueban **al pedir montar** (antes, al elegir servidor). Si hay que renovar: pantalla de credenciales → vuelve a la lista y monta. La caducidad se ve en cada tarjeta, con su botón **Renew credentials**. |
| Estado "montado" | Se pregunta al backend; no se guarda aparte. Desaparece `state["mounted_per_perfil"]`. |
| Montajes antiguos | Antes de montar un perfil se desmontan los de la versión por bucket (`<base>/<perfil>/<bucket>`) y se borran sus carpetas vacías. Si alguno no se puede desmontar (fichero abierto), no se monta y se avisa con los buckets que lo impiden (decisión del 2026-11-23). |
| rclone sin montaje | Antes de montar, se para cualquier `rclone mount <perfil>:` que siga vivo sin montaje (corte de red, desmontaje a mano, sesión anterior), para que no compartan la caché. |
| Opciones de rclone | Todo montaje de MinIO lleva `--read-only --links` y las opciones de rendimiento de la fase 0, definidas en un solo sitio (`s3_mount.py`). Las de caché que se pasen al arrancar la app (`_vfs_flags_from_argv`) van después y mandan sobre las fijas. |

## Arquitectura

### Backend: `shared/bifrost_backend/mount/`

```text
mount/
  mount_points.py  NUEVO (fase 1)  la carpeta de montaje: dónde está y en qué estado
  processes.py     NUEVO (fase 1)  listar y parar procesos `rclone mount` (sale de s3_mount.py)
  legacy.py        NUEVO (fase 2)  desmontar los montajes por bucket de la versión anterior
  s3_mount.py                      API pública: montar, desmontar, dónde está montado
  preflight.py                     requisitos (WinFsp, fuse-t, FUSE); + `fuse_env()` (fase 1)
common/rclone_mount.py             + `obtener_letra_unidad_disponible()` (fase 1, sale de transfer/smb.py)
```

La letra de unidad va a `common/rclone_mount.py` y no a `mount/`: la usan los montajes de MinIO y los de NetApp
(`transfer/smb.py`), y así `transfer/` no depende de `mount/`. En la práctica NetApp solo monta en modo web (OOD,
Linux), pero no se duplica la función.

| Módulo | API |
|---|---|
| `mount_points.py` | Fase 1: `mount_base()` · `normalized(path)` · `prepare_mount_point(path) -> bool` · `wait_unmounted(path, seconds)` · `force_unmount(path)`. Fase 2: `profile_folder(perfil) -> Path` (macOS/Linux, `<base>/<perfil>`) |
| `processes.py` | Fase 1: `rclone_mount_processes()` · `parse_mount_processes(output, windows=)` (puro, con tests) · `pids_serving(mount_point)` · `stop_pid(pid)` · `stop_mount_process(proc)`. Fase 2: `drive_letter_in(command_line, perfil) -> str \| None` (la letra de un `rclone mount <perfil>: X:`) |
| `legacy.py` | `bucket_mounts(perfil) -> list[Path]` (las carpetas que siguen montadas como un bucket) · `remove_empty_folders(perfil)`. Desmontarlas lo hace `s3_mount`, con la misma rutina que el resto de desmontajes |
| `s3_mount.py` | `mount_profile(perfil) -> str` · `unmount_profile(perfil) -> bool` · `active_mount_point(perfil, *, scan=False) -> str \| None` · `desmontar_todos_los_mounts_s3()` (mismo nombre: lo registra `main.py`) |

- **`active_mount_point`** es la única forma de saber si un perfil está montado. Mira primero los rclone de esta
  sesión (`args[2] == f"{perfil}:"`, `args[3]` es el punto de montaje). Con `scan=True` busca también restos de
  sesiones anteriores: en macOS/Linux, `is_mounted(profile_folder(perfil))`; en Windows, la letra con
  `drive_letter_in` sobre `rclone_mount_processes()` (PowerShell, lento: solo al cargar la pantalla).
- **`mount_profile`** mantiene lo que ya hace `mount_rclone_S3_prefix_to_folder`: si está montado y responde,
  lo devuelve; si el sistema quitó el montaje y su rclone sigue vivo (macOS tras un corte de red), lo para;
  `fuse_env()`, `--allow-non-empty` fuera de Windows y las opciones de caché de `_vfs_flags_from_argv()`.
  Comando: `rclone mount <perfil>: <destino> --read-only --links <opciones de rendimiento> [--allow-non-empty]
  [opciones de caché de argv]`. Las opciones de rendimiento son una constante (`_MOUNT_OPTIONS`) que usan el montaje
  por perfil y, mientras exista, el de un bucket.
- **Log temporal de rclone**: `rclone_log_path("mount", perfil)` (antes `mount-<perfil>-<bucket>.log`).
- **Windows**: el punto de montaje es `"X:"` (como NetApp). Para abrirlo en el Explorador se pasa `"X:\\"`.
- `backend.py`: se exportan las funciones nuevas (fase 2) y se quitan `mount_rclone_S3_prefix_to_folder`,
  `resolver_mount_point_destino` y `desmontar_punto_montaje` (solo las usa `views/mount.py`; fase 3).

### Vistas: `bifrost-mount/src/views/`

```text
views/
  servers.py        NUEVO  pantalla con una tarjeta por servidor; monta y desmonta en hilos
  server_card.py    NUEVO  componente de una tarjeta
  renew_dialog.py   NUEVO  diálogo "Renew MinIO credentials" (sale de mount.py, sin cambios de lógica)
  winfsp_dialog.py  NUEVO  instalación de WinFsp (sale de mount.py, sin cambios de lógica)
  mount.py          se borra
```

- **`ServerCard`** (clase pequeña): recibe nombre, endpoint y callbacks `on_mount`, `on_unmount`, `on_renew`.
  Expone `.control` y `.refresh(mount_point, session_info, busy, status_text)`. Muestra: nombre, endpoint,
  caducidad de credenciales (mismos colores que el badge actual), estado (montado en `X:` / `~/rclone-mounts/…`),
  botones **Mount** / **Unmount** / **Renew credentials**. Doble clic = Mount. No llama al backend.
- **`build_servers_content(page, *, credenciales_ldap, on_credentials, mount_on_load=None, on_back=None)`**:
  - Al cargar: `active_mount_point(perfil, scan=True)` de cada perfil en un hilo; luego refresca las tarjetas.
  - Mount: si `backend.hay_que_renovar_credenciales(perfil, usuario)` → `on_credentials(perfil, None)`; si no,
    `mount_profile` en `backend.safe_thread`, y al terminar `open_in_file_browser` + "✅ Mounted!".
  - Unmount: `unmount_profile` en un hilo; si falla, `show_issue(UNMOUNT_FAILED)`.
  - Renew: `renew_dialog` → `on_credentials(perfil, dias)`.
  - Errores: `MountError` → `show_issue(..., title="Could not mount the server", context=perfil)`;
    `WinFspMissingError` → `winfsp_dialog`.
  - "Ocupado" por tarjeta: se puede montar `minio` mientras se desmonta `minio-archive`. Toda mutación de la UI con
    `backend.ui_call`.
  - `mount_on_load`: el perfil que hay que montar al volver de la pantalla de credenciales.

### Flujo en `bifrost-mount/src/main.py`

```text
update → login → servers ─ Mount / doble clic ─ ¿hay que renovar? ─ sí → credenciales → servers(mount_on_load=perfil)
                    ▲                                              └ no → monta → abre la carpeta
                    └──────────── Renew credentials (días) → credenciales → servers
```

- `go_servers(mount: str | None = None)` sustituye a `go_minio`, `on_minio_selected`, `_go_credentials_or_mount` y
  `go_mount`.
- `on_credentials(perfil, dias)`: `build_credentials_content(perfil_rclone=perfil, endpoint=…,
  extra_config=MINIO_SERVERS[perfil]["IRB"].get("extra_rclone_config"), duracion_dias=dias,
  on_continue=lambda: go_servers(mount=perfil if dias is None else None), on_back=go_servers)`.
- `state` se queda con `credenciales_ldap`; desaparecen `servidor_minio`, `perfil_rclone`, `endpoint` y
  `mounted_per_perfil`.
- `shared/bifrost_frontend/views/minio.py` **no se toca**: lo usa bifrost-transfer.

## Fase 1 — `refactor(mount)`: separar sin cambiar el comportamiento

Los cuerpos de las funciones se mueven sin cambios; solo pierden el `_` las que se usan desde otro módulo. Los
nombres públicos de `s3_mount.py` (`mount_rclone_S3_prefix_to_folder`, `desmontar_punto_montaje`…) se quedan hasta
la fase 2, que cambia su comportamiento.

- `mount/processes.py`: `_rclone_mount_processes` → `rclone_mount_processes`, con el análisis de la salida aparte en
  `parse_mount_processes` (puro); `_rclone_pids_serving` → `pids_serving`; `_stop_pid` → `stop_pid`;
  `_stop_mount_process` → `stop_mount_process`; `_taskkill`. El análisis de Windows usa `ntpath.normcase`, que en
  Windows es el mismo `os.path.normcase` de antes y permite probarlo desde macOS.
- `mount/mount_points.py`: `_get_s3_mount_base` → `mount_base`, `_normalized` → `normalized`,
  `_prepare_mount_point` → `prepare_mount_point`, `_wait_unmounted` → `wait_unmounted`, `_force_unmount_path` →
  `force_unmount`, `_mount_point_is_stale` → `_is_stale` (solo la usa `prepare_mount_point`).
- `mount/preflight.py`: `_fuse_env` → `fuse_env`. `s3_mount.py` ya no importa funciones privadas de `preflight`.
- `common/rclone_mount.py`: `obtener_letra_unidad_disponible` (desde `transfer/smb.py`, que la importa de aquí;
  `backend.py` la sigue exportando).
- Tests: `tests/unit/backend/test_processes.py` (salida real de `ps` en macOS, con el `go-nfsv4` de fuse-t, que
  lleva la carpeta de montaje en su línea de comandos y no es rclone; salida con la forma de PowerShell).
- Documentación técnica: `docs/agent/backend.md`, `docs/agent/architecture.md`, `docs/development/backend.md`,
  `docs/development/testing.md`.
- Comprobar: los tests pasan, y la app monta y desmonta un bucket igual que antes (macOS, tras
  `uv sync --reinstall-package bifrost-shared`).

## Fase 2 — `feat(mount)`: API por perfil

- `mount_points.py`: `profile_folder`. `processes.py`: `drive_letter_in`.
- `legacy.py`: `unmount_bucket_mounts`.
La fase 2 solo **añade**: la pantalla de buckets sigue funcionando hasta la fase 3, que la sustituye y borra lo que
ya no se usa. Así cada commit deja la app funcionando, y la API nueva se puede revisar y probar (tests y Windows)
antes de cambiar la pantalla.

- `s3_mount.py`: `mount_profile`, `unmount_profile`, `active_mount_point`; adaptar `desmontar_todos_los_mounts_s3`
  y el log temporal para que sirvan a los dos tipos de montaje.
- `s3_mount.py`: constante `_MOUNT_OPTIONS` con las opciones de rendimiento de la fase 0, en el comando de los dos
  tipos de montaje (el de un bucket las usa ya desde esta fase).
- `backend.py`: exportaciones.
- Tests: `drive_letter_in` en `test_processes.py`, con líneas de `Get-CimInstance` (comillas, mayúsculas, rutas
  con espacios, perfil que es prefijo de otro: `minio` frente a `minio-archive`); `profile_folder` y la detección
  de carpetas de montajes antiguos en `test_mount_points.py`.
- Documentación técnica de los módulos que cambian.

## Fase 3 — `feat(mount)`: pantalla y flujo

- `server_card.py`, `servers.py`, `renew_dialog.py`, `winfsp_dialog.py`; borrar `views/mount.py`.
- Borrar lo que solo usaba la pantalla de buckets: `mount_rclone_S3_prefix_to_folder`, `resolver_mount_point_destino`,
  `desmontar_punto_montaje` y sus exportaciones en `backend.py`.
- `main.py`: flujo nuevo y docstring de "Flujo de vistas".
- Prueba manual en macOS (`flet run` en `bifrost-mount/`):
  1. Con montajes por bucket de la versión anterior activos → montar `minio` los desmonta y monta el perfil.
  2. Montar `minio` y `minio-archive` a la vez; desmontar uno, el otro sigue.
  3. Cerrar la app con montajes → se desmontan todos; abrir con un resto de una sesión anterior → la tarjeta lo
     marca como montado y Unmount lo quita.
  4. Credenciales caducadas → pantalla de credenciales → vuelve y monta.
  5. Sin VPN → error traducido en la tarjeta.
  6. QuPath abre una imagen de `~/rclone-mounts/minio/<bucket>/…`; repetir la medida de listado sin carga.
- Windows y Linux: misma lista, a mano en esas máquinas (no se puede probar desde el Mac de desarrollo). Punto crítico en Windows:
  detectar la letra de una sesión anterior (`drive_letter_in`).

- Documentación en el mismo commit: `docs/user/mount-buckets.md` (pasos, rutas `X:\<bucket>` /
  `~/rclone-mounts/<servidor>/<bucket>`, tabla de problemas: desaparecen ⟳ y "Unmount all"), `docs/agent/frontend.md`,
  `docs/agent/architecture.md` y la documentación de desarrollo del frontend.

## Fases 2 y 3 — lo implementado (2026-11-23)

Respecto a lo planificado arriba:

- `processes.py`: además de `drive_letter_in`, `server_mount_pids(perfil)` (los `rclone mount <perfil>: …` de un
  servidor entero, estén donde estén) y `pids_serving(..., processes=)` para no leer los procesos varias veces.
- `s3_mount.py`: `_stop_lost_mounts` para, antes de montar, el rclone de esta sesión cuyo montaje se perdió y
  cualquier otro del mismo servidor sin montaje (lo encontró la prueba real: el rclone de una prueba a mano seguía
  vivo tras un `umount -f`), y espera hasta 5 s a que suelte la caché. `_unmount` es la única rutina de desmontaje:
  la usan `unmount_profile`, los montajes antiguos y el cierre de la app. `BucketMountsBusyError(buckets)` (un
  `MountError` con `UNMOUNT_FAILED`) cuando un montaje antiguo no se deja desmontar.
- `mount_points.py`: `is_stale` pasa a ser pública (la usa `legacy.py`) y `prepare_mount_point` pierde la rama de
  Windows (ahora se monta en una letra, no en una carpeta).
- `common/rclone_output.py`: nuevo `NO_DRIVE_LETTER` (406); las pistas de `MOUNT_BUSY` (402) y `UNMOUNT_FAILED`
  (404) ya no nombran "Unmount all".
- Vistas: `ServerCard` es una clase con `.control` y `show(...)`; el botón Mount pasa a "📂 Open" cuando el servidor
  está montado. `servers.py` lleva el estado por servidor (ocupado, dónde está montado) y lo comprueba al cargar
  con `active_mount_point(scan=True)`.
- `main.py`: `go_servers(mount=)` y `go_credentials(servidor, días)`; el estado se queda en `credenciales_ldap`.
- Tests: `test_processes.py` (`server_mount_pids`, `drive_letter_in`) y `test_s3_mount.py` (el comando de
  montaje: servidor entero, solo lectura, opciones de rendimiento en orden, `--allow-non-empty` solo fuera de
  Windows y las opciones de caché de argv al final). No hay `test_mount_points.py`: lo que queda en ese módulo toca
  el sistema de ficheros.
- Documentación: técnica (agente y desarrollo), de usuario (`mount-buckets.md`, `troubleshooting.md`: 402, 404 y
  406) y `README.md`. De paso se corrigieron dos textos desfasados: el error de fuse-t que falta (ya era
  `MountError(FUSE_MISSING_MACOS)`, no `EnvironmentError`) y la guía de usuario, que decía que en el montaje se
  podía escribir (siempre ha sido de solo lectura).

Comprobado: 48 tests en verde; prueba real del backend en macOS (script fuera del repo): con un montaje antiguo
`minio:test` y el rclone huérfano de una prueba a mano, `mount_profile("minio")` para el huérfano, desmonta el
antiguo, borra las 22 carpetas vacías de la versión anterior y monta el servidor (0,8 s); `active_mount_point` lo
encuentra con y sin `scan`; volver a montar no lanza otro rclone; `unmount_profile` lo desmonta y no queda ningún
rclone.

Pendiente: la prueba manual de la app (lista de la fase 3) en macOS, Windows y Linux; capturar en Windows la salida
real de `Get-CimInstance` para sustituir la de los tests.

## Fase 4 — `docs(mount)`: revisión final

- Pasar el skill `docs-update` sobre toda la rama: revisar `AGENTS.md`, `README.md` y lo que se haya quedado atrás.

## Riesgos y pendientes

- **Ficheros nuevos que tardan en verse (`--dir-cache-time 12h`)**: MinIO no avisa a rclone de los cambios, así que
  un listado se guarda 12 h. Un fichero subido a MinIO (por ejemplo con Bifrost transfer) puede no aparecer en el
  montaje hasta 12 h después, o hasta desmontar y volver a montar. Decidido (2026-11-23): se queda en 12 h de
  momento. Volver a montar refresca las listas (viven en la memoria de rclone), pero con el montaje por servidor
  desmonta todos sus buckets y hay que cerrar antes los ficheros abiertos. Explicarlo en la documentación de usuario.
- **Disco usado por la caché (`--vfs-cache-max-size 10G`)**: cada servidor tiene su carpeta dentro de la caché
  (`vfs/minio/…`, `vfs/minio-archive/…`), así que varios servidores montados no se pisan. El límite es por montaje
  (hasta 30 GB con los tres), pero un fichero que no se lee en 1 h sale de la caché (`--vfs-cache-max-age`, 1 h por
  defecto), así que en la práctica guarda lo leído en la última hora. rclone no avisa: al pasar el límite borra los
  ficheros menos usados, y no puede borrar los abiertos, así que puede pasarlo un rato. Si el disco se llena, el
  programa que lee recibe un error de lectura y rclone lo deja en su log (pasa al log técnico al desmontar). La caché
  va a la carpeta de caché del usuario (`~/Library/Caches/rclone`, `%LOCALAPPDATA%\rclone`, `~/.cache/rclone`); en una
  sesión DCV del clúster está en el home, que puede tener cuota (`--cache-dir` al arrancar la app permite moverla).
- **Dos rclone del mismo servidor con caché**: la ayuda de rclone avisa de que dos procesos con la misma caché y el
  mismo remoto (o solapado) pueden corromperla. El diseño lo evita con un solo montaje por servidor: antes de montar,
  `mount_profile` busca si ese perfil ya está montado (en Windows, también por los procesos, con `drive_letter_in`,
  antes de elegir letra nueva), y los montajes por bucket se desmontan antes de montar el perfil. La app instalada
  (versión anterior) monta sin caché, así que no la usa.

- **Letra de una sesión anterior en Windows**: depende de leer la línea de comandos con PowerShell; esa parte no se
  ha probado nunca en Windows (ya anotado para `rclone_mount_processes`; el análisis de su salida tiene tests, pero con una salida que no se ha
  capturado en Windows).
- **Letras ocupadas**: hasta tres servidores más los shares de NetApp (Bifrost transfer). Si no quedan letras,
  error claro en la tarjeta.
- **La letra cambia entre sesiones**: un acceso directo a `X:` puede no valer la próxima vez. Documentarlo.
- **Usuario sin acceso a un servidor**: el montaje puede funcionar y verse vacío. Revisar qué devuelve rclone en
  la fase 3 y, si se puede, avisar.
- **Futuro**: nombre de la carpeta base más amigable que `rclone-mounts` (con limpieza de la carpeta antigua).
- **Futuro**: botón **Refresh** en la tarjeta del servidor para ver ficheros nuevos sin desmontar: lanzar rclone con
  `--rc` y pedirle `vfs/refresh`. Sin probar.

## Pruebas de la caché (pendientes)

Antes de dar por buenas las opciones de caché (`--vfs-cache-mode full`, `--vfs-cache-max-size 10G`) y de decidir si
hace falta `--vfs-cache-min-free-space`, comprobar que nada falla por falta de espacio. Se pueden hacer con la app
(desde la fase 2 el montaje de un bucket ya lleva las opciones) o con `rclone mount` a mano con las mismas opciones.
Ver el tamaño de la caché con `du -sh <carpeta de caché>/vfs/*` (macOS: `~/Library/Caches/rclone`; Windows:
`%LOCALAPPDATA%\rclone`; Linux: `~/.cache/rclone`).

1. **Dónde va y cómo crece**: abrir con QuPath un fichero grande (p. ej. un `.qptiff` de 3,7 GB de
   `ccl-group-worm/facility_data/histopathology/`) y comprobar que la caché crece en `vfs/<servidor>/…`.
2. **Límite de 10 GB**: leer más de 10 GB de un mismo servidor en menos de una hora (3 o 4 de esos ficheros). Con los
   ficheros cerrados, en 1-2 minutos (`--vfs-cache-poll-interval`) la caché debe volver por debajo de 10 GB; con
   ficheros abiertos puede pasarlo. Anotar cuánto llega a ocupar.
3. **Caducidad de 1 h**: dejar el montaje una hora sin leer y comprobar que la caché se vacía.
4. **Al cerrar la app**: ver si la caché se queda en disco al desmontar y si se limpia al volver a montar.
5. **Varios servidores**: montar `minio` y `minio-archive` y leer de los dos: cada uno en su carpeta de la caché,
   sin errores.
6. **Disco lleno (sin arriesgar el disco del equipo)**: crear un volumen pequeño y usarlo como caché. En macOS:
   `hdiutil create -size 2g -fs APFS -volname cachetest ~/cachetest.dmg`, `hdiutil attach ~/cachetest.dmg` y montar
   a mano con `--cache-dir /Volumes/cachetest`. Abrir un fichero mayor de 2 GB y anotar qué pasa: si QuPath da un
   error o se queda colgado, si el montaje sigue respondiendo después y qué deja rclone en su log. Al terminar,
   desmontar, `hdiutil detach /Volumes/cachetest` y borrar `~/cachetest.dmg`.
7. **Con `--vfs-cache-min-free-space`**: repetir la prueba 6 añadiendo, por ejemplo, `--vfs-cache-min-free-space 500M`
   y comprobar si así la lectura funciona. Si funciona y la 6 falla, añadir la opción a `_MOUNT_OPTIONS` con un valor
   que tenga sentido para los discos de los usuarios.
8. **Windows**: pruebas 1, 2 y 5 con la caché en `%LOCALAPPDATA%\rclone`.
9. **Sesión DCV del clúster**: ver la cuota del home (`quota -s` o `df -h ~`) y si caben 10 GB por servidor en
   `~/.cache/rclone`; si no, decidir una `--cache-dir` fuera del home.
