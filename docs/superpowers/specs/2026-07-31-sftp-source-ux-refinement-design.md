# Diseño: Refinamiento UX del origen SFTP (bifrost-transfer)

**Fecha:** 2026-07-31
**Rama:** feature/sftp
**Alcance:** bifrost-transfer (vista de copia), backend compartido
**Precede a:** este spec construye sobre `2026-07-30-sftp-source-design.md` (ya implementado) — no lo reemplaza, lo ajusta tras pruebas manuales.

---

## Resumen

Tras probar el origen SFTP implementado según el spec del 2026-07-30, se detectan tres ajustes de UX necesarios:

1. **Contraseña opcional** — el diálogo de conexión exige hoy usuario+contraseña; algunas cuentas SFTP no tienen contraseña.
2. **Sin "crear carpeta" en el origen** — el browser SFTP reutiliza `build_rclone_browser`, que incluye una sección "Add subfolder" pensada para el *destino* S3 (carpeta virtual, se crea al copiar). No tiene sentido en un *origen*: no existe la carpeta hasta que el usuario la crea en el servidor SFTP real.
3. **Selección de fichero o carpeta** — el listado SFTP (`rclone lsd`) solo devuelve subcarpetas, igual que el browser de destino S3. A diferencia de S3 (montado en HDD lento, por eso no se listan ficheros ahí), un servidor SFTP permite listar ficheros sin coste apreciable. El usuario debe poder elegir como origen **una carpeta entera o un fichero individual dentro de ella** (mismo comportamiento que ya existe para origen local vía los botones 📄 File / 📁 Folder).

---

## Decisión de diseño: adaptar `build_rclone_browser`, no duplicarlo

`build_rclone_browser` es usado hoy por dos llamantes: el browser de destino S3 (línea ~2544) y el browser de origen SFTP (línea ~2305). Ambos comparten la parte más compleja y delicada del componente — breadcrumb, navegación, fallback de timeout con entrada manual de path, manejo de errores, caché de listado de raíz — que es idéntica entre los dos casos de uso.

Lo que diverge entre destino y origen es pequeño:
- si se ofrece "crear carpeta" (solo destino),
- si se listan también ficheros además de carpetas (solo origen SFTP),
- qué función de rclone se usa para listar (`lsd` vs `lsjson`).

Se adapta el componente existente con dos parámetros nuevos en vez de duplicarlo, para no mantener dos copias de la lógica de timeout/errores/caché.

---

## Sección 1: Backend — `shared/bifrost_backend/backend.py`

### Contraseña opcional

`crear_perfil_rclone_sftp` no cambia de firma ni de lógica — ya acepta cualquier `password: str`, incluida cadena vacía (`rclone obscure ""` es válido y produce un valor ofuscado utilizable). El cambio es únicamente de validación en el frontend (ver Sección 2).

### Nueva función: `rclone_lsjson`

Sustituye a `rclone_lsd` **solo** en el browser de origen SFTP. Lista carpetas y ficheros de un nivel en una única llamada:

```python
def rclone_lsjson(perfil: str, path: str = "", timeout: int = 15) -> list[dict]:
    """
    Lista carpetas y ficheros (un nivel) de un path en un perfil rclone, vía JSON.

    Returns:
        Lista de dicts {"name": str, "is_dir": bool}, carpetas primero,
        luego alfabético case-insensitive dentro de cada grupo.

    Raises:
        RuntimeError: si rclone lsjson falla.
    """
    rclone = get_rclone_executable()
    target = f"{perfil}:{path}" if path else f"{perfil}:"

    result = subprocess.run(
        [rclone, "lsjson", target],
        capture_output=True,
        text=True,
        timeout=timeout,
        **_subprocess_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone lsjson failed (code {result.returncode})")

    entradas = json.loads(result.stdout or "[]")
    items = [{"name": e["Name"], "is_dir": bool(e.get("IsDir"))} for e in entradas]
    return sorted(items, key=lambda i: (not i["is_dir"], i["name"].lower()))
```

`rclone_lsd` no se toca — sigue siendo lo que usa el browser de destino S3.

---

## Sección 2: Frontend — `bifrost-transfer/src/main.py`

Todos los textos de UI y mensajes de error introducidos o tocados en esta sección (labels, tooltips, texto de botones, mensajes de validación) van en **inglés**, siguiendo la convención ya establecida en el resto de la vista de copia (el punto 3 de "Convenciones y gotchas críticas" en `CLAUDE.md` reserva español solo para comentarios/docstrings/README, no para la UI de `bifrost-transfer`).

### Diálogo de conexión SFTP

- Validación en `connect()`: `if not host or not user or not pwd:` → `if not host or not user:`.
- El campo Password no cambia de hint (ya está resuelto en el código actual).
- El resto del flujo (crear perfil, validar conexión, mensajes de error) no cambia.

### `build_rclone_browser` — dos parámetros nuevos

```python
def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str, bool], None],   # (path, is_file) — antes solo (path,)
    initial_path: str = "",
    lab_filter_enabled: bool = False,
    endpoint: str | None = None,
    allow_mkdir: bool = True,      # NUEVO — destino S3 lo deja en True (sin cambios)
    show_files: bool = False,      # NUEVO — destino S3 lo deja en False (sin cambios)
) -> tuple[ft.Column, Callable]:
```

**`allow_mkdir=False`** (usado por el browser SFTP): `mkdir_section.visible` pasa de `bool(path)` a `allow_mkdir and bool(path)`. La sección "Add subfolder to destination" nunca se muestra.

**`show_files=True`** (usado por el browser SFTP):
- `_navigate` llama a `backend.rclone_lsjson(perfil, path, ...)` en vez de `backend.rclone_lsd(...)`, normalizado a `list[dict]` en ambos casos (cuando `show_files=False`, los resultados de `rclone_lsd` se envuelven como `{"name": n, "is_dir": True}` para reutilizar el mismo código de render).
- Filas de fichero (`is_dir=False`): icono `INSERT_DRIVE_FILE_OUTLINED`, sin icono de flecha (`CHEVRON_RIGHT`), `on_click` no navega — llama a `_toggle_file_selection(path)`.
- `_toggle_file_selection(path)`: si el fichero clicado ya estaba seleccionado, deselecciona (`nav_state["selected_file"] = None`); si no, lo selecciona y desmarca cualquier selección previa. Actualiza el estilo de la fila (borde `C_PRIMARY` + fondo resaltado en la fila seleccionada, estilo normal en la anterior) sin recargar el listado. Llama a `on_select(path if selected else nav_state["current_path"], selected)`.
- Navegar a otra carpeta (clic en fila de carpeta o breadcrumb) limpia `nav_state["selected_file"]` de forma implícita — `_navigate` reconstruye `folder_col` desde cero.
- Al entrar en `_navigate(path)`, se llama a `on_select(path, False)` como hoy (sin cambios) — esto ya limpia la selección "efectiva" de cara al llamante en cuanto se navega.

**Callers actualizados:**
- Destino S3 (línea ~2544): `on_select` recibe ahora `(path, is_file)`, ignora el segundo argumento (siempre `False` porque `show_files=False` ahí) — solo se actualiza la firma de la lambda, sin cambio de comportamiento.
- Origen SFTP (línea ~2305): `_on_sftp_select(path: str, is_file: bool)` guarda `_sftp_dest_path = {"value": path, "is_file": is_file}`.

### Modal SFTP (`_open_sftp_browser_modal`)

- `build_rclone_browser(..., allow_mkdir=False, show_files=True)`.
- El botón de confirmación cambia de texto dinámicamente entre **"Select this folder"** y **"Select this file"** según `_sftp_dest_path["is_file"]`, actualizado dentro de `_on_sftp_select` (`confirm_btn.text = ...; page.update()` — o el patrón equivalente ya usado en el resto del fichero para mutar texto de botones).
- Al confirmar: `origen_tf.value = f"{sftp_state['perfil']}:{path}"` — sin cambios; el formato es idéntico exista o no selección de fichero, por lo que `do_copy`/`do_check` no requieren ningún cambio (mismo argumento que en el spec original: un fichero suelto vía SFTP se comporta igual que hoy con 📄 File local).

---

## Manejo de errores

Sin cambios respecto al spec original — `rclone_lsjson` propaga `RuntimeError`/`subprocess.TimeoutExpired` exactamente igual que `rclone_lsd`, por lo que el manejo existente de timeout (fallback a path manual) y de errores genéricos en `build_rclone_browser` cubre también el nuevo listado sin modificaciones.

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `shared/bifrost_backend/backend.py` | Nueva función `rclone_lsjson` junto a `rclone_lsd` |
| `bifrost-transfer/src/main.py` | `build_rclone_browser`: params `allow_mkdir`, `show_files`, listado normalizado a dicts, filas de fichero seleccionables, `on_select` con segundo argumento `is_file`; diálogo de conexión SFTP con password opcional; modal SFTP con botón de confirmación dinámico |
| `CLAUDE.md` | Actualizar el gotcha #12 (origen SFTP) para mencionar selección de fichero o carpeta, ausencia de "Add subfolder" en el origen y password opcional |
| `README.md` | Actualizar la mención de SFTP añadida en el spec del 2026-07-30 (descripción de `bifrost-transfer`) para reflejar que se puede elegir carpeta completa o fichero individual, y que la contraseña es opcional |

---

## Restricciones y gotchas

- `allow_mkdir`/`show_files` son específicos del llamante, no del perfil rclone — el destino S3 sigue sin listar ficheros porque MinIO está montado en HDD lento (ver gotcha ya documentado), no por limitación técnica del componente.
- La selección de fichero es puramente de UI (resaltado + segundo argumento en `on_select`); no se introduce ningún concepto nuevo de "origen tipo fichero" en el backend — sigue siendo una cadena `perfil:path` que `do_copy`/`do_check` consumen sin distinguir si apunta a carpeta o fichero (rclone ya lo resuelve solo).
- No hay suite de tests automatizada; validación manual con `flet run`, cubriendo:
  1. Conectar sin contraseña a una cuenta SFTP que la acepta vacía.
  2. Navegar una carpeta con subcarpetas y ficheros mezclados → se listan ambos, ficheros sin flecha de navegación.
  3. Seleccionar un fichero → botón cambia a "Select this file" → confirmar → `origen` = `perfil:path/fichero` → copy funciona.
  4. Deseleccionar el fichero (clic de nuevo) → botón vuelve a "Select this folder" → confirmar selecciona la carpeta actual.
  5. Navegar a otra carpeta tras seleccionar un fichero → selección se limpia automáticamente.
  6. Confirmar que "Add subfolder" no aparece en ningún punto del browser SFTP.
  7. Confirmar que el browser de destino S3 sigue funcionando exactamente igual que antes (sin ficheros listados, con "Add subfolder" disponible).
