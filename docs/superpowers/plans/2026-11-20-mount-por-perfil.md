# Plan: montar cada servidor MinIO entero (un volumen por perfil)

Rama: `feature/mount-por-perfil` (desde `develop`). Última actualización: 2026-11-20.

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Pruebas manuales con rclone (Windows y macOS) | **Hecha** |
| 1 | `refactor(mount)`: separar procesos y puntos de montaje, sin cambiar el comportamiento | Pendiente |
| 2 | `feat(mount)`: API por perfil y limpieza de los montajes por bucket | Pendiente |
| 3 | `feat(mount)`: pantalla de servidores con tarjetas y flujo en `main.py` | Pendiente |
| 4 | `docs(mount)`: documentación de usuario, agente y desarrollo | Pendiente |

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
- **`--volname` no hace falta**: sin él, rclone ya llama al volumen como el perfil (`minio`).
- **`/Volumes` descartado**: es de `root`; montar ahí exige `sudo` y rclone no crea la carpeta. Se monta en
  `~/rclone-mounts/<perfil>`.
- **El Finder enseña `fuse-t`**: es el nombre de máquina del NFS local de fuse-t (`127.0.0.1 fuse-t` en
  `/etc/hosts`). No cambia con `--volname` ni con `-o backend=smb`. Se acepta: es cosmético.
- **Listados lentos**: un `ls -la` de una carpeta con muchas imágenes tardó más de 2 minutos, medido con una
  búsqueda `rclone lsf -R` en paralelo. Repetir la medida sin carga en la fase 3.

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
| Montajes antiguos | Antes de montar un perfil se desmontan los de la versión por bucket (`<base>/<perfil>/<bucket>`). |

## Arquitectura

### Backend: `shared/bifrost_backend/mount/`

```text
mount/
  mount_points.py  NUEVO  dónde se monta cada perfil; puro, sin procesos ni rclone
  processes.py     NUEVO  listar y parar procesos `rclone mount` (sale de s3_mount.py)
  legacy.py        NUEVO  desmontar los montajes por bucket de la versión anterior
  s3_mount.py             API pública: montar, desmontar, dónde está montado
  preflight.py            sin cambios (WinFsp, fuse-t, FUSE)
```

| Módulo | API |
|---|---|
| `mount_points.py` | `mount_base() -> Path` (Windows `C:/rclone-mounts`, solo para los montajes antiguos; resto `~/rclone-mounts`) · `profile_folder(perfil) -> Path` (macOS/Linux) · `free_drive_letter() -> str \| None` (sale de `transfer/smb.py`, que la importa de aquí) · `drive_letter_in(command_line, perfil) -> str \| None` (la letra de un `rclone mount <perfil>: X:`) |
| `processes.py` | `rclone_mount_processes() -> list[tuple[int, str]]` · `pids_serving(mount_point) -> list[int]` · `stop_pid(pid)` · `stop_mount_process(proc)` (taskkill del árbol en Windows) |
| `legacy.py` | `unmount_bucket_mounts(perfil) -> list[str]`: desmonta cada `<base>/<perfil>/<bucket>` montado y devuelve los que no se pudieron desmontar |
| `s3_mount.py` | `mount_profile(perfil) -> str` · `unmount_profile(perfil) -> bool` · `active_mount_point(perfil, *, scan=False) -> str \| None` · `desmontar_todos_los_mounts_s3()` (mismo nombre: lo registra `main.py`) |

- **`active_mount_point`** es la única forma de saber si un perfil está montado. Mira primero los rclone de esta
  sesión (`args[2] == f"{perfil}:"`, `args[3]` es el punto de montaje). Con `scan=True` busca también restos de
  sesiones anteriores: en macOS/Linux, `is_mounted(profile_folder(perfil))`; en Windows, la letra con
  `drive_letter_in` sobre `rclone_mount_processes()` (PowerShell, lento: solo al cargar la pantalla).
- **`mount_profile`** mantiene lo que ya hace `mount_rclone_S3_prefix_to_folder`: si está montado y responde,
  lo devuelve; si el sistema quitó el montaje y su rclone sigue vivo (macOS tras un corte de red), lo para;
  `_fuse_env()`, `--allow-non-empty` fuera de Windows y las opciones de caché de `_vfs_flags_from_argv()`.
  Comando: `rclone mount <perfil>: <destino> --read-only --links [--allow-non-empty] [vfs flags]`.
- **Log temporal de rclone**: `rclone_log_path("mount", perfil)` (antes `mount-<perfil>-<bucket>.log`).
- **Windows**: el punto de montaje es `"X:"` (como NetApp). Para abrirlo en el Explorador se pasa `"X:\\"`.
- `backend.py`: se exportan las funciones nuevas y se quitan `mount_rclone_S3_prefix_to_folder`,
  `resolver_mount_point_destino` y `desmontar_punto_montaje` (solo las usa `views/mount.py`).

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

- Crear `processes.py` con lo que hoy está en `s3_mount.py` (`_rclone_mount_processes`, `_rclone_pids_serving`,
  `_stop_pid`, `_taskkill`, `_stop_mount_process`).
- Crear `mount_points.py` con `_get_s3_mount_base` y `obtener_letra_unidad_disponible` (renombradas);
  `transfer/smb.py` la importa de aquí.
- Comprobar: la app monta y desmonta un bucket igual que antes (macOS).

## Fase 2 — `feat(mount)`: API por perfil

- `mount_points.py`: `profile_folder`, `drive_letter_in`.
- `legacy.py`: `unmount_bucket_mounts`.
- `s3_mount.py`: `mount_profile`, `unmount_profile`, `active_mount_point`; adaptar `desmontar_todos_los_mounts_s3`
  y el log temporal; borrar las funciones por bucket.
- `backend.py`: exportaciones.
- Tests (`tests/unit/backend/test_mount_points.py`): `profile_folder`; `drive_letter_in` con líneas reales de
  `Get-CimInstance` (comillas, mayúsculas, rutas con espacios, perfil que es prefijo de otro: `minio` frente a
  `minio-archive`); detección de carpetas de montajes antiguos.

## Fase 3 — `feat(mount)`: pantalla y flujo

- `server_card.py`, `servers.py`, `renew_dialog.py`, `winfsp_dialog.py`; borrar `views/mount.py`.
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

## Fase 4 — `docs(mount)`

- `docs/user/mount-buckets.md`: pasos, rutas (`X:\<bucket>` / `~/rclone-mounts/<servidor>/<bucket>`), tabla de
  problemas (desaparecen ⟳ y "Unmount all").
- `docs/agent/backend.md`, `docs/agent/frontend.md`, `docs/development/backend.md` (y frontend): módulos y API.
- Revisar `AGENTS.md` y `README.md`. Hacerlo con el skill `docs-update`.

## Riesgos y pendientes

- **Letra de una sesión anterior en Windows**: depende de leer la línea de comandos con PowerShell; esa parte no se
  ha probado nunca en Windows (ya anotado para `_rclone_mount_processes`).
- **Letras ocupadas**: hasta tres servidores más los shares de NetApp (Bifrost transfer). Si no quedan letras,
  error claro en la tarjeta.
- **La letra cambia entre sesiones**: un acceso directo a `X:` puede no valer la próxima vez. Documentarlo.
- **Usuario sin acceso a un servidor**: el montaje puede funcionar y verse vacío. Revisar qué devuelve rclone en
  la fase 3 y, si se puede, avisar.
- **Futuro**: nombre de la carpeta base más amigable que `rclone-mounts` (con limpieza de la carpeta antigua).
