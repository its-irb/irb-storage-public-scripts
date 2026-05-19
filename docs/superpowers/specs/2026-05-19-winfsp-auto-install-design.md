# Auto-instalación de WinFsp en Windows

**Fecha:** 2026-05-19
**Estado:** Diseño aprobado, pendiente de plan de implementación
**Apps afectadas:** `bifrost-mount`, `bifrost-transfer`

---

## Motivación

Hoy, cuando un usuario de Windows intenta montar un bucket S3 y no tiene WinFsp instalado, la app muestra un diálogo con la URL `https://winfsp.dev` y el usuario tiene que descargar e instalar el MSI manualmente. Queremos que la app ofrezca instalarlo automáticamente, descargando la última versión publicada en el repo oficial.

WinFsp **no puede empaquetarse como binario portable** (como rclone) porque incluye un driver de kernel (`winfsp-x64.sys`) que tiene que estar firmado, registrado con el SCM de Windows y cargado por el SO. La instalación por MSI con elevación UAC es obligatoria al menos una vez por máquina.

## Decisiones de diseño

- **Fuente de la última versión:** GitHub Releases API (`api.github.com/repos/winfsp/winfsp/releases/latest`). Es la fuente oficial real (winfsp.dev/rel/ sirve los mismos MSIs); JSON estable, fácil de parsear.
- **Descarga bajo demanda:** no bundle del MSI dentro de la app. Requiere internet la primera vez; instalador de la app más liviano.
- **UX:** preguntar antes de instalar (diálogo Sí / Cancelar). Más transparente que lanzar msiexec directamente; el UAC del sistema seguirá saliendo además del prompt de la app.
- **Aplicar a ambas apps**, ya que `bifrost-transfer` también permite montar prefijos S3.

## Cambios en `shared/bifrost_backend/backend.py`

### Nueva excepción

```python
class WinFspMissingError(EnvironmentError):
    """Falta WinFsp en Windows. Se distingue del EnvironmentError genérico
    para que la UI pueda ofrecer auto-instalación."""
```

### Nuevas funciones

1. **`_winfsp_latest_msi_url() -> tuple[str, str]`**
   - Llama a `https://api.github.com/repos/winfsp/winfsp/releases/latest`.
   - Parsea el JSON; en `assets[]` busca el primero cuyo `name` termina en `.msi`.
   - Devuelve `(browser_download_url, tag_name)`.
   - Si la API falla o no hay MSI: levanta `RuntimeError` con mensaje claro.

2. **`_download_winfsp_msi(url: str, dest_path: Path) -> Path`**
   - Descarga con `urllib.request.urlopen` (consistente con resto del backend).
   - Destino: `Path(tempfile.gettempdir()) / f"winfsp-{tag}.msi"`.
   - Verifica que el fichero existe y tiene tamaño > 0 tras la descarga.
   - Devuelve el path al MSI.

3. **`install_winfsp_windows(page) -> bool`**
   - Orquestador. Ejecuta:
     1. `_winfsp_latest_msi_url()` → URL + tag.
     2. `_download_winfsp_msi(...)` → path local.
     3. `subprocess.run(["msiexec", "/i", str(msi_path), "/qb", "/norestart"], check=False)`.
     4. Inspecciona `returncode`:
        - `0` → éxito.
        - `3010` → éxito pero requiere reinicio (warning, tratamos como éxito).
        - `1602` → usuario canceló UAC / instalación (no es error; devolver `False`).
        - cualquier otro → error.
     5. Llama `_check_winfsp_windows()` para confirmar.
   - Devuelve `True` si tras la instalación WinFsp está presente, `False` si el usuario canceló, levanta excepción en error real.
   - Todas las actualizaciones de UI (mensajes de progreso) vía `ui_call(page, ...)`.

### Modificar `mount_rclone_S3_prefix_to_folder()` (línea ~604)

```python
elif sistema == "Windows":
    if not _check_winfsp_windows():
        raise WinFspMissingError("WinFSP not detected")
```

(El mensaje del `raise` deja de incluir la URL: la UI decide qué mostrar.)

## Cambios en las apps

### `bifrost-mount/src/main.py` (línea ~1200) y `bifrost-transfer/src/main.py` (línea ~2133)

Sustituir el bloque actual:

```python
except EnvironmentError as ex:
    err_str = str(ex)
    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
```

por:

```python
except backend.WinFspMissingError:
    _prompt_install_winfsp(page, on_success=<reintentar mount>)
except EnvironmentError as ex:
    err_str = str(ex)
    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
```

Donde `_prompt_install_winfsp(page, on_success)`:
1. Muestra diálogo: "WinFsp no está instalado. ¿Descargar e instalar la última versión ahora?" — botones **Instalar** / **Cancelar**.
2. Si **Cancelar** → diálogo informativo con link a `https://winfsp.dev` (comportamiento actual).
3. Si **Instalar** → `backend.safe_thread(page, lambda: _do_install(...))`:
   - Muestra estado "Descargando WinFsp…" / "Instalando…".
   - Llama `backend.install_winfsp_windows(page)`.
   - Si devuelve `True` → cierra el diálogo de progreso y ejecuta `on_success()` (reintento automático del mount).
   - Si devuelve `False` (usuario canceló UAC) → diálogo informativo, no reintenta.
   - Si excepción → diálogo error con link manual a `winfsp.dev`.

El helper `_prompt_install_winfsp` se duplica en cada app (siguiendo el patrón actual donde la UI específica vive en `main.py`), o se factoriza a `bifrost_frontend.frontend` si crece. Decisión durante implementación.

## Flujo end-to-end

```
Usuario pulsa Montar
  → backend.mount_rclone_S3_prefix_to_folder()
      ├─ raises WinFspMissingError
      │   → diálogo "WinFsp no detectado. ¿Instalar?"
      │      ├─ Instalar
      │      │   → safe_thread: descarga MSI → msiexec /qb (UAC)
      │      │      ├─ instalado OK → reintenta el mount automáticamente
      │      │      ├─ usuario cancela UAC → diálogo informativo
      │      │      └─ error red/MSI → diálogo error con link manual
      │      └─ Cancelar → diálogo informativo con link manual
      ├─ raises EnvironmentError (FUSE Linux/macOS) → diálogo actual sin cambios
      └─ raises otro → diálogo "Mount error" actual
```

## Comando msiexec

```
msiexec /i "<path al .msi>" /qb /norestart
```

- `/qb` — UI básica (barra de progreso). Preferido a `/qn` para que el usuario vea progreso real del driver install.
- `/norestart` — evita reinicio forzado; WinFsp normalmente no lo necesita.
- UAC se dispara automáticamente porque el MSI marca `RequireAdmin` internamente; no necesitamos `runas`.

Exit codes manejados:
| Código | Significado | Tratamiento |
|---|---|---|
| 0 | OK | éxito |
| 3010 | OK, requiere reinicio | éxito (mostrar warning opcional) |
| 1602 | Usuario canceló | devolver False, no es error |
| 1603 | Fatal error during install | excepción |
| otros | error | excepción |

## Fuera de alcance

- Bundle del MSI en `assets/bin/` (descartado: el usuario prefiere descarga).
- Verificación de hash/firma adicional (msiexec ya valida Authenticode del MSI firmado por WinFsp).
- Fallback automático a `winfsp.dev/rel/` si GitHub API falla (si falla, se muestra error con URL manual).
- Caché del MSI descargado entre ejecuciones (se redescarga si el usuario lo intenta de nuevo; son ~2 MB).
- Auto-actualización de WinFsp ya instalado (solo instala si falta).
- Soporte para flujos no-admin / per-user (WinFsp requiere admin por diseño).

## Tests

No hay suite automatizada en el repo. Validación manual:
1. Máquina Windows sin WinFsp: lanzar `flet run` en `bifrost-mount`, intentar montar → verificar prompt, instalación, reintento del mount.
2. Cancelar el UAC → verificar que la app muestra mensaje y no se cuelga.
3. Cancelar el diálogo previo → verificar comportamiento informativo actual.
4. Mismas pruebas en `bifrost-transfer` con el flujo de montar prefijo S3.
5. Sin red: verificar mensaje de error razonable con link manual.

## Archivos a modificar

- `shared/bifrost_backend/backend.py` — nueva excepción, 3 funciones nuevas, modificar `mount_rclone_S3_prefix_to_folder`.
- `bifrost-mount/src/main.py` — sustituir bloque `except EnvironmentError` (~línea 1200), añadir `_prompt_install_winfsp`.
- `bifrost-transfer/src/main.py` — idem en ~línea 2133.
- `docs/wiki/log.md` — entrada al cerrar la tarea (convención del repo).
