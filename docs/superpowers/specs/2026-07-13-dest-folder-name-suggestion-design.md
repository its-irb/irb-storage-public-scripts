# Diseño: Sugerencia automática del nombre de carpeta destino

**Fecha:** 2026-07-13
**Rama:** feature/guardarailes-useragent-excludes
**Alcance:** bifrost-transfer (vista de copia)

---

## Resumen

Hoy, al copiar una carpeta origen a un bucket destino, el usuario tiene que crear a mano la subcarpeta destino escribiendo su nombre en el campo `new-folder-name` del browser de destino (`_do_mkdir`, virtual — no llama a rclone). Esto es fricción innecesaria cuando lo habitual es que la subcarpeta destino se llame igual que la carpeta origen.

Este cambio autorellena ese campo con el nombre base de la carpeta/fichero origen en cuanto el usuario lo selecciona, dejándolo editable. El usuario sigue confirmando la creación de la subcarpeta pulsando el botón mkdir (📁+) o Enter, igual que hoy — no se automatiza esa parte.

---

## Usuarios objetivo

Cualquier usuario de `bifrost-transfer` en el flujo de copia (desktop o web). No cambia el comportamiento para quien no usa subcarpetas de destino (sigue pudiendo copiar directo a la raíz del bucket).

---

## Sección 1: Helper de extracción de nombre — `main.py`

Nueva función junto a los demás helpers de la vista de copia:

```python
def _extraer_nombre_carpeta(ruta: str) -> str:
    """Devuelve el último segmento no vacío de una ruta, separando por / y \\."""
    partes = [p for p in re.split(r"[\\/]+", ruta.strip()) if p]
    return partes[-1] if partes else ""
```

Funciona tanto con rutas locales Windows (`C:\...\proyecto_x`) como con rutas SMB/remote ya traducidas (`smb-share/carpeta/proyecto_x`) y con las rutas devueltas por `show_local_fs_modal` en modo web.

---

## Sección 2: Sugerencia y guardia anti-sobrescritura — dentro de `_build_copy_content`

```python
_suggested_name = {"value": ""}

def _suggest_dest_folder(ruta: str) -> None:
    nombre = _extraer_nombre_carpeta(ruta)
    if not nombre:
        return
    actual = (new_folder_tf.value or "").strip()
    if actual == "" or actual == _suggested_name["value"]:
        new_folder_tf.value = nombre
        _suggested_name["value"] = nombre
        page.update()
```

- Solo sobrescribe `new_folder_tf.value` si está vacío o si coincide con la última sugerencia automática — así no pisa una edición manual del usuario.
- `new_folder_tf` y `page` ya están disponibles en el scope de `_build_copy_content` (mismo closure que `build_rclone_browser`/`dest_browser`).

---

## Sección 3: Puntos de enganche

Se llama a `_suggest_dest_folder(ruta)` inmediatamente después de cada asignación de `origen_tf.value` en `main.py`:

| Línea aprox. | Contexto |
|---|---|
| `2272` | `_pick_file` (desktop, FilePicker de fichero) |
| `2282` | `_pick_folder` (desktop, FilePicker de carpeta) |
| `2315` | `_open_folder_browser` → `_picked` (web, modal carpeta) |
| `2322` | `_open_file_browser` → `_picked` (web, modal fichero) |

**No** se engancha en la restauración de sesión web (`_snap_origen`, línea `~2751`): es un estado ya completado (el usuario ya decidió aplicar o no la sugerencia antes de desconectar) y volver a disparar la sugerencia podría pisar un `copy_destino` ya restaurado.

---

## Flujo completo (caso de uso)

1. Usuario pulsa "📁 Folder" y elige `C:\datos\proyecto_x`
2. `origen_tf.value` = ruta traducida; `new_folder_tf.value` se autorellena con `proyecto_x`
3. Usuario navega el browser de destino hasta un bucket
4. Ve el campo ya relleno con `proyecto_x` — lo deja tal cual o lo edita
5. Pulsa el botón mkdir (📁+) → path destino pasa a ser `bucket/proyecto_x` (virtual, como hoy)
6. Copia normalmente

Si el usuario cambia de origen después de haber editado el campo a mano, la edición manual se respeta (no se sobrescribe).

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `bifrost-transfer/src/main.py` | Añadir `_extraer_nombre_carpeta`, `_suggest_dest_folder`, `_suggested_name`; enganchar en los 4 puntos de selección de origen |

---

## Restricciones y gotchas

- No se toca `_do_mkdir` ni la restricción existente de requerir un bucket seleccionado (`nav_state["current_path"]`) antes de aplicar la subcarpeta.
- Si el nombre extraído queda vacío (ruta termina en separador o está vacía), no se sugiere nada — el campo se deja como está.
- Requiere `import re` en `main.py` si no está ya importado.
- No hay suite de tests automatizada en este repo; validación manual con `flet run` (desktop) y `flet run --web` (modales web), cubriendo: autorelleno al elegir origen, aplicación vía botón mkdir, y no sobrescritura de una edición manual al cambiar de origen.
