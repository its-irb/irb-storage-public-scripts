# Reglas críticas y gotchas

Conocimiento transversal que condiciona cualquier cambio. Detalles técnicos en
[backend.md](backend.md) y [frontend.md](frontend.md).

## threading y Flet

1. **`ui_call` obligatorio**: toda mutación de `control.controls` o
   `page.update()` desde un hilo de background debe envolverse en
   `backend.ui_call(page, fn)`. Usar `page.run_thread()` directamente causa
   `IndexError` en `_compare_lists` del diff walker de Flet. Para crear hilos,
   usar `backend.safe_thread(page, target)` — captura excepciones y las
   muestra en diálogo.
2. **`threading.Timer`**: envolver el callback
   (`lambda: ui_call(page, fn)`), nunca pasar la función de navegación
   directamente.
3. **Codificación de consola en Windows**: `main.py` reenvuelve
   `sys.stdout`/`sys.stderr` en UTF-8 al arrancar (bloque `TextIOWrapper`).
   No tocar.

## Estructura y acoplamiento

4. **El backend importa del frontend**: `backend.py` usa `show_dialog` y
   `C_ERROR` de `bifrost_frontend.frontend`. Hay acoplamiento (no es un
   backend "puro").
5. **`config.py` debe ser importable como módulo top-level** en cada app — el
   backend hace `from config import APP_INFO`.
6. **`TAG_PROFILES` y `LAB_ACRONYMS` son la fuente canónica en
   `bifrost-transfer/src/meta_fields.py`**: el formulario de copia y el Tag
   Manager usan `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS`,
   `build_lab_filter_widget` y `detect_profile` de ahí. Para añadir, renombrar
   o reordenar un campo, perfil o lab, cambiarlo **solo** en `meta_fields.py`.
   `LAB_ACRONYMS` debe contener los acrónimos exactos del tag `acronym` de los
   buckets MinIO.

## Comportamiento visible que hay que preservar

7. **Credenciales STS**: si quedan >3 días se reutilizan; <3 días se renuevan
   automáticamente por 7 días (`STS_RENEWAL_THRESHOLD_DAYS` /
   `STS_AUTO_RENEWAL_DAYS` en `main.py`).
8. **Auto-instalación de WinFsp (solo `bifrost-mount`, Windows)**: si falta
   WinFsp al montar, el backend lanza `WinFspMissingError` (subclase de
   `EnvironmentError`) y la UI ofrece descargar la última release oficial
   (`github.com/winfsp/winfsp`) vía `backend.install_winfsp_windows()`.
   Requiere UAC; el MSI se cachea en `%TEMP%`. Mensajes de este flujo en
   **inglés** (excepción al punto 9). `bifrost-transfer` no tiene este flujo.
9. **Idioma**: comentarios, docstrings y mensajes de UI en **español**
   (excepción anterior de WinFsp).
10. **Visibilidad condicional en el formulario de copia**: las secciones
    METADATA, botones de acción y LOG OUTPUT (`bottom_col.visible=False`)
    permanecen ocultos hasta que se selecciona un bucket destino. El toggle
    vive en `on_browser_select`: `path` no vacío → visible; vuelta a raíz →
    oculto.
11. **Filtro de laboratorio en browsers de buckets**: el browser destino de la
    vista de copia y el del Tag Manager incluyen "Filter by lab…"
    (`build_lab_filter_widget`), que lee el tag `acronym` de cada bucket con
    `backend.get_bucket_tags` en paralelo (`ThreadPoolExecutor`). Se oculta al
    navegar dentro de un bucket y reaparece en la raíz. Solo filtra a nivel de
    buckets (root).
12. **Origen SFTP efímero (`bifrost-transfer`)**: el botón "🌐 SFTP" crea un
    perfil rclone temporal (`sftp-src-<random>`, tipo `sftp`, contraseña
    ofuscada con `rclone obscure`) en `rclone.conf`. Por seguridad **no debe
    sobrevivir a la sesión**: se borra al pulsar Disconnect (✕), al salir de
    la vista de copia (`on_back`) y se barre cualquier `sftp-src-*` huérfano
    tras cada login (`backend.limpiar_perfiles_rclone_con_prefijo`). El
    diálogo de conexión solo exige host y usuario (contraseña opcional). El
    browser SFTP (`allow_mkdir=False, show_files=True`) no ofrece crear
    carpeta y lista ficheros vía `backend.rclone_lsjson`; el browser destino
    S3 solo lista carpetas vía `backend.rclone_lsd` porque el listado de MinIO
    sobre HDD es lento. Se puede elegir como origen una carpeta o un fichero
    individual (mismo formato `perfil:path`).

## Higiene de repositorio

13. **No commitear** `.venv/`, `dist/`, `build/`, `src/version.py` generado ni
    los `pyproject.toml` locales de las apps. Ver `.gitignore`.

## Pendiente de verificar

- `docs/wiki/` y `docs/superpowers/specs/` son referenciados por la
  documentación heredada pero **no existen** en el repositorio. No crear
  referencias nuevas a esas rutas.
