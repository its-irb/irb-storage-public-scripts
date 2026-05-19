# bifrost-mount: mejora del sistema de logging

**Fecha:** 2026-05-19  
**Scope:** `bifrost-mount/src/main.py` únicamente

---

## Objetivo

Mejorar los logs persistentes de bifrost-mount para que cada entrada incluya timestamp completo y cubra todas las acciones relevantes del usuario: inicio de app, login, selección de perfil y bucket, mount, unmount y errores.

---

## Cambios

### 1. Timestamp en `_write_to_log_file`

Modificar la función existente (línea 86) para prefijar `[YYYY-MM-DD HH:MM:SS]` a cada línea:

```python
def _write_to_log_file(msg: str) -> None:
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            line = msg if msg.endswith("\n") else msg + "\n"
            f.write(f"[{timestamp}] {line}")
    except Exception:
        pass
```

Los logs de credenciales ya existentes ganan timestamp automáticamente sin cambios adicionales.

### 2. Helper global `_log_event`

Añadir junto a `_write_to_log_file`:

```python
def _log_event(msg: str) -> None:
    _write_to_log_file(msg)
```

Thin wrapper para llamadas de eventos de usuario. Sin color ni UI — solo archivo.

### 3. Eventos a instrumentar

| Punto en el código | Función/sección | Evento |
|---|---|---|
| `main()` o `page_init` | inicio de app | `APP start — bifrost-mount v<version>` |
| `do_login` antes de auth | `_build_login_content` | `LOGIN attempt — user: <user>` |
| `do_login` en éxito | `_build_login_content` | `LOGIN success — user: <user>` |
| `do_login` en error | `_build_login_content` | `LOGIN failed — user: <user> — <msg>` |
| selección de perfil MinIO | `view_minio` | `PROFILE selected — <perfil> (<endpoint>)` |
| `_select_bucket` | `build_rclone_browser` | `BUCKET selected — <bucket>` |
| `do_mount` inicio | `_build_mount_bucket` | `MOUNT start — bucket: <bucket>, profile: <perfil>` |
| `do_mount` éxito | `_build_mount_bucket` | `MOUNT success — bucket: <bucket>, path: <mp>` |
| `do_mount` WinFspMissingError | `_build_mount_bucket` | `MOUNT error (WinFsp missing) — bucket: <bucket>` |
| `do_mount` EnvironmentError | `_build_mount_bucket` | `MOUNT error (FUSE/WinFSP) — bucket: <bucket> — <msg>` |
| `do_mount` Exception | `_build_mount_bucket` | `MOUNT error — bucket: <bucket> — <msg>` |
| `_unmount_bucket` inicio | `build_rclone_browser` | `UNMOUNT — bucket: <bucket>, path: <mp>` |
| `_unmount_bucket` error | `build_rclone_browser` | `UNMOUNT error — bucket: <bucket> — <msg>` |
| `_unmount_all` inicio | `build_rclone_browser` | `UNMOUNT ALL — <n> mounts` |
| WinFsp install OK | `_prompt_install_winfsp` | `WINFSP install success` |
| WinFsp install error | `_prompt_install_winfsp` | `WINFSP install error — <msg>` |

---

## Formato de log resultante

```
[2026-05-19 14:23:01] APP start — bifrost-mount v1.0.42
[2026-05-19 14:23:05] LOGIN attempt — user: ona.perez
[2026-05-19 14:23:06] LOGIN success — user: ona.perez
[2026-05-19 14:23:08] PROFILE selected — irb-s3 (https://minio.irbbarcelona.org)
[2026-05-19 14:23:10] BUCKET selected — research-data
[2026-05-19 14:23:11] MOUNT start — bucket: research-data, profile: irb-s3
[2026-05-19 14:23:12] MOUNT success — bucket: research-data, path: C:\Users\operez\bifrost-mount\research-data
[2026-05-19 14:31:04] UNMOUNT — bucket: research-data, path: C:\Users\operez\bifrost-mount\research-data
```

---

## Archivos modificados

- `bifrost-mount/src/main.py` — único archivo tocado

## Archivos NO modificados

- `shared/bifrost_backend/backend.py` — el logging es responsabilidad del frontend
- `bifrost-transfer/` — no tiene este flujo

---

## Restricciones

- No se añade ningún panel de log visible en la UI (solo archivo)
- Los mensajes de log están en **inglés** (consistente con el resto de bifrost-mount)
- No se usa el módulo `logging` de Python — se mantiene el helper existente
