# Frontend — apps Flet (`bifrost-mount` / `bifrost-transfer`)

## Estructura por app (layout común)

```text
<app>/
  pyproject-template.toml  # Plantilla; pyproject.toml se genera localmente
  installer.iss            # Inno Setup (Windows)
  build-macos.sh
  src/
    main.py                # GUI Flet — punto de entrada
    config.py              # APP_INFO = {"flavour": ..., "name": ..., "description": ...}
    version.py             # __version__ — generado por CI/build
    assets/bin/            # rclone(.exe) — descargado con los downloaders (no versionado)
    frameworks/            # fuse_t.framework (mount, macOS) — idem
    storage/               # (solo transfer) datos temporales
```

Tamaño actual: `bifrost-mount/src/main.py` ≈ 1414 líneas;
`bifrost-transfer/src/main.py` ≈ 4577 líneas (modo web + Tag Manager);
`bifrost-transfer/src/meta_fields.py` ≈ 645 líneas.

## Inicialización de cada `main.py`

```python
from bifrost_backend import backend
from bifrost_frontend.frontend import *      # paleta + componentes
from config import APP_INFO                  # {"flavour": "mount"|"transfer", ...}
```

Después: 1) detecta modo de ejecución (`IS_WEB`); 2) reenvuelve
`sys.stdout`/`sys.stderr` en UTF-8 (consola Windows) — **no tocar**; 3)
configura el log persistente (`~/bifrost-mount-logs/` en mount,
`~/bifrost-logs/` en transfer); 4) define
`main(page: ft.Page)` y arranca con `ft.app(target=main, ...)`.

## Flujo de vistas

```text
bifrost-mount (desktop puro):
  view_update → view_login → view_minio → view_credentials (auto) → view_mount

bifrost-transfer (desktop):
  view_update → view_login → view_minio → view_credentials (auto) → view_copy

bifrost-transfer (cluster Linux, BIFROST_CLUSTER=1):
  view_update → view_login → view_shares → view_minio → view_credentials → view_copy
```

`view_copy` contiene navegador de carpetas rclone para el destino
(`build_rclone_browser`), selector de origen (SMB/local/SFTP), opciones de
copia y panel de log en vivo (`ft.ListView` con `auto_scroll=True`).

## Credenciales STS — auto-renovación

Constantes en cada `main.py`: `STS_RENEWAL_THRESHOLD_DAYS = 3`,
`STS_AUTO_RENEWAL_DAYS = 7`. Si quedan >3 días de validez se reutilizan;
si no, se renuevan automáticamente por 7 días mostrando progreso. No hay
botón manual de renovación en el flujo normal.

## `meta_fields.py` (solo bifrost-transfer)

- `TAG_PROFILES` — perfiles de metadatos (IRB Standard, Histopathology);
  fuente canónica usada por el formulario de copia y el Tag Manager.
- `LAB_ACRONYMS` — acrónimos exactos que aparecen en el tag `acronym` de los
  buckets MinIO.
- `build_meta_fields(..., prefill_values: dict[str, str] | None)` — construye
  los controles del formulario; `prefill_values` pre-rellena con tags
  existentes.
- `build_lab_filter_widget(...)` — widget "Filter by lab…" de los browsers.
- `detect_profile(tags: dict[str, str])` — detecta el perfil que encaja con
  un dict de tags.

## Modo web (`bifrost-transfer`, Open OnDemand) — esencial

```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- Servidor ASGI: **Hypercorn** (un único event loop asyncio). Cada pestaña
  abre su propio WebSocket con su propio objeto `page`.
- Sesiones en `_WEB_SESSIONS` (dict global por `username`; TTL = vida del
  proceso Hypercorn). **Nunca se guarda la contraseña LDAP.**
- Reconexión: al reabrir la pestaña el usuario solo reintroduce la contraseña;
  `_replay` restaura estado, repite las últimas 200 líneas del buffer y
  reengancha el proceso rclone si sigue vivo.
- Log dispatcher `_dispatch_log` con **throttle de 150 ms** (buffer cap 5000
  líneas, múltiples callbacks por usuario, lock `_dispatch_lock`). Sin
  throttle, Hypercorn satura y las reconexiones se cuelgan.
- Autosave: al terminar cada copy/check, `_autosave_log()` vuelca el buffer a
  `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log` (crítico en web: el buffer
  en memoria está capeado y el log completo solo existe en disco).

Detalle completo en [../development/frontend.md](../development/frontend.md).

## Regla absoluta de thread-safety

> Toda mutación de `control.controls` o llamada a `page.update()` desde fuera
> del event loop de Flet debe envolverse en `backend.ui_call(page, fn)`.

Solo los event handlers de Flet (botones, dialogs) pueden llamar
`page.update()` directamente. Con `threading.Timer`, envolver el callback:
`threading.Timer(0.1, lambda: ui_call(page, fn)).start()`.

## Convenciones de UI

- **Todo en español** (labels, mensajes, nombres de controles UI). Excepción:
  los mensajes del flujo de instalación de WinFsp en `bifrost-mount` están en
  inglés.
- **Colores**: solo constantes de `bifrost_frontend.frontend`
  (`C_PRIMARY`, `C_ERROR`, …). No hardcodear hex.
- **Botones**: preferir `btn_primary` / `btn_secondary` sobre `ft.Button` crudo.
- **Diálogos de error**: `show_dialog(page, "Error", msg, color=C_ERROR)`.
- **Logs de copia** (transfer/web): pasar siempre por `_dispatch_log`; nunca
  `log_list.controls.append(...)` directo desde un hilo.
