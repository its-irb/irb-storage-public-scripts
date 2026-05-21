# Spec: Tag Manager — editor freeform de tags por fichero

**Fecha:** 2026-05-21  
**Rama:** feature/bifrost-transfer-tags  
**Fichero principal afectado:** `bifrost-transfer/src/main.py`

---

## Contexto

El Tag Manager de `bifrost-transfer` tiene dos paneles: izquierdo (browser de buckets/carpetas/ficheros S3) y derecho (editor de tags). El editor derecho actualmente siempre muestra el editor de perfil (campos fijos de `TAG_PROFILES`), tanto si hay una carpeta seleccionada como si hay un fichero. Al clicar un fichero, los tags reales de S3 se leen y pre-rellenan los campos del perfil — pero los tags que no pertenezcan al perfil son invisibles, y la UX no deja claro que los campos provienen del fichero.

El objetivo de este cambio es que al clicar un fichero el panel derecho muestre sus tags reales como filas editables (clave + valor), con posibilidad de añadir, eliminar y guardar. El editor de perfil se mantiene para la selección de carpetas.

---

## Restricciones de S3

- **Máximo 10 tags por objeto S3.** Si el editor ya tiene 10 filas, el botón "Añadir tag" queda deshabilitado.
- **Máximo 256 caracteres** por campo (clave o valor). Los TextFields muestran `max_length=256` y rechazan entrada adicional.

Estas restricciones son límites reales de la API de S3/MinIO.

---

## Comportamiento del panel derecho

### Cuando hay un fichero seleccionado (`sel["type"] == "file"`)

El panel derecho muestra el **editor freeform**:

```
TAGS DEL FICHERO
📄 path/al/fichero.ext

  Clave                Valor
  [project_name    ]   [MyProject     ] [×]
  [compute_node    ]   [cluster01     ] [×]
  [sample_type     ]   [              ] [×]
  ...

  [+ Añadir tag]    ← deshabilitado si hay 10 filas

  ──────────────────────────────────────
  Pre-rellenar desde perfil: [IRB Standard ▼] [Pre-fill]

  [Save tags]   ✅ Tags guardados
```

### Cuando hay una carpeta/prefijo seleccionado (`sel["type"] == "prefix"`)

El panel derecho muestra el **editor de perfil** — sin cambios respecto al comportamiento actual.

---

## Detalle de interacciones

| Acción | Resultado |
|---|---|
| Clicar fichero en browser | Lee tags de S3 (hilo background), construye filas clave/valor, muestra editor freeform |
| Pulsar [×] en una fila | Elimina la fila del editor (no guarda hasta Save) |
| Pulsar [+ Añadir tag] | Añade fila vacía `["", ""]`; deshabilitado si hay ≥ 10 filas |
| Cambiar perfil en dropdown + Pre-fill | Carga claves del perfil: si la clave ya existe en las filas conserva su valor; las claves nuevas se añaden con valor vacío. No elimina claves no pertenecientes al perfil |
| Pulsar [Save tags] | Construye tagset `{clave: valor}` ignorando filas con clave vacía, llama `apply_tags_to_object` en hilo background, muestra estado inline ✅ / ❌ |
| Navegar a otra carpeta o fichero | El editor freeform se limpia y se reconstruye para la nueva selección |

---

## Validaciones

- Clave vacía en una fila: la fila se ignora al guardar (no error, no incluida en el tagset).
- Claves duplicadas: la última fila prevalece (comportamiento de dict). No se muestra error — S3 también las sobreescribe.
- Si el fichero no tiene tags en S3: el editor arranca vacío (0 filas).
- Errores de red al leer o guardar: mensaje inline en rojo, botón Save re-habilitado.

---

## Implementación

### Nuevas estructuras de estado

```python
_file_tag_rows: list[dict]  # cada dict: {"key_tf": TextField, "val_tf": TextField, "row": ft.Row}
_file_tags_col: ft.Column   # contiene las filas visibles del editor freeform
_file_editor_section: ft.Container  # sección completa del editor freeform (visible/hidden)
_profile_editor_section: ft.Container  # sección del editor de perfil actual (visible/hidden)
```

### Funciones nuevas / modificadas

- `_build_file_editor_row(key="", value="") -> ft.Row`: crea una fila clave+valor+[×]. Conecta on_change de los TextFields para actualizar el contador y deshabilitar [+ Añadir tag] si hay 10.
- `_populate_file_editor(tags: dict[str, str])`: limpia `_file_tag_rows`, crea una fila por cada tag, actualiza `_file_tags_col`.
- `_on_add_tag_row(e)`: añade fila vacía si `len(_file_tag_rows) < 10`.
- `_on_prefill_from_profile(e)`: lee perfil activo, añade claves que falten, conserva valores existentes.
- `_on_save_file_tags(e)`: construye tagset, llama `apply_tags_to_object` en safe_thread.
- `_select_file` (modificada): tras leer los tags, llama `_populate_file_editor` y activa el modo freeform.
- `_navigate` (modificada): al navegar, desactiva el modo freeform y activa el modo perfil.

### Alternancia de modos

Se controla con `visible` en los contenedores:
```python
_file_editor_section.visible  = (sel["type"] == "file")
_profile_editor_section.visible = (sel["type"] != "file")
```

### Backend

Sin cambios. Se reutilizan `get_object_tags` y `apply_tags_to_object` existentes en `shared/bifrost_backend/backend.py`.

---

## Fuera de alcance

- Reordenar filas de tags con drag-and-drop.
- Validación de claves reservadas de S3.
- Historial de cambios por fichero.
- Edición masiva freeform sobre múltiples ficheros (eso sigue siendo responsabilidad del editor de perfil).
