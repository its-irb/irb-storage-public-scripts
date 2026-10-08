# Diseño: Selector de perfil de metadatos en el formulario de copia

**Fecha:** 2026-06-09  
**Rama:** `feature/profiles-copy`  
**App:** `bifrost-transfer`

---

## Resumen

El formulario de copia de bifrost-transfer tiene los campos de metadatos (tags S3) fijados al perfil "IRB Standard". Se añade un selector de perfil para que el usuario pueda elegir qué conjunto de campos quiere rellenar antes de copiar, con los mismos controles ricos (dropdowns, datepicker, multi-freetext) que ya tiene el Tag Manager.

---

## Contexto del código actual

- `TAG_PROFILES` y `FieldType` viven en `bifrost-transfer/src/main.py` (líneas 92–133).
- `_build_copy_content` construye `meta_fields` hardcodeado a `TAG_PROFILES["IRB Standard"]` (líneas 1856–1862), usando siempre `styled_field` (TextField plano) independientemente del tipo de campo.
- `_build_tag_manager_content` tiene `_rebuild_tag_fields` (líneas 3057–3394) que ya construye controles ricos por tipo de campo, pero es una función closure interna.
- `_ws_save()` persiste estado de copia en `_WEB_SESSIONS` (líneas 174–200); no incluye el perfil de tags.

---

## Arquitectura

### Fichero nuevo: `bifrost-transfer/src/meta_fields.py`

Contiene exactamente tres cosas (extraídas de `main.py`):

| Símbolo | Tipo | Descripción |
|---|---|---|
| `FieldType` | `Enum` | Tipos de campo: TEXT, UNISELECT, MULTISELECT, MULTIFREETEXT, DATE, NUMBER |
| `TAG_PROFILES` | `dict[str, list[tuple]]` | Fuente de verdad de perfiles y campos |
| `build_meta_fields(profile_name, page, fields_dict)` | función | Construye los controles Flet para el perfil dado |

**Firma de `build_meta_fields`:**
```python
def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,          # se rellena in-place: key → control
) -> ft.Column:                 # columna lista para insertar en el árbol
```

- Itera `TAG_PROFILES[profile_name]` y construye el control apropiado por `FieldType`.
- Para UNISELECT/MULTIFREETEXT/DATE: misma lógica que `_rebuild_tag_fields` actual (el código se mueve, no se duplica).
- Todos los tipos exponen el valor final en `.value` del control registrado en `fields_dict`, por lo que `do_copy()` no necesita cambios.
- No llama a `page.update()` — responsabilidad del caller.
- Importa solo `flet as ft` y `bifrost_frontend.frontend` (sin tocar `main.py`). Sin circular import.

### Cambios en `main.py`

#### 1. Imports
```python
# Eliminar definición de FieldType y TAG_PROFILES
# Añadir:
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields
```

#### 2. `_ws_save()` — añadir campo de perfil
```python
"copy_tag_profile": state.get("copy_tag_profile", list(TAG_PROFILES.keys())[0]),
```

#### 3. `_build_copy_content` — sección de metadatos refactorizada

**Selector de perfil** (nuevo, encima de los campos de metadatos):
- `ft.Dropdown` con las claves de `TAG_PROFILES` como opciones.
- Valor inicial: `web_session.get("copy_tag_profile")` si existe, si no `list(TAG_PROFILES.keys())[0]`.
- `active_copy_profile = {"name": <valor_inicial>}` — dict mutable para closures.

**Campos dinámicos:**
- `meta_fields: dict = {}` — mutable, se rellena en cada build.
- `meta_container = ft.Container()` — reemplaza `meta_grid`; su `content` se reemplaza al cambiar perfil.
- Build inicial: `col = build_meta_fields(active_copy_profile["name"], page, meta_fields); meta_container.content = col`.

**Handler de cambio de perfil:**
```
on_change del Dropdown:
  1. Guardar valor anterior en active_copy_profile["name"]
  2. Llamar show_confirm(page, "Confirm", "Changing the profile will clear all metadata. Continue?",
       on_confirm=<rebuild>, on_cancel=<restaurar dropdown>)

on_confirm:
  1. meta_fields.clear()
  2. col = build_meta_fields(nuevo_perfil, page, meta_fields)
  3. meta_container.content = col
  4. active_copy_profile["name"] = nuevo_perfil
  5. Si IS_WEB y web_session: web_session["copy_tag_profile"] = nuevo_perfil
  6. page.update()

on_cancel:
  1. profile_dd.value = active_copy_profile["name"]  ← restaurar al anterior
  2. page.update()
```

**`do_copy()` sin cambios:** `metadatos = {k: (tf.value or "").strip() for k, tf in meta_fields.items()}` funciona para todos los tipos.

**Layout:** columna única (igual que Tag Manager), en lugar del grid 4+3 actual. Funciona para cualquier número de campos.

#### 4. `_build_tag_manager_content` — simplificación de `_rebuild_tag_fields`

```python
def _rebuild_tag_fields(profile_name, target_container=None, target_fields=None):
    container = target_container or card_container
    fields    = target_fields    or tag_fields
    fields.clear()
    col = build_meta_fields(profile_name, page, fields)
    container.content = card(col, padding=16)
    page.update()
```

Sin cambios de comportamiento para el Tag Manager.

---

## Persistencia en sesión web

| Clave en `_WEB_SESSIONS` | Tipo | Descripción |
|---|---|---|
| `copy_tag_profile` | `str` | Nombre del último perfil seleccionado en el formulario de copia |

Se guarda en `_ws_save()` y se lee en `_build_copy_content` igual que `copy_origen`/`copy_destino`.

---

## Ficheros afectados

| Fichero | Cambio |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | **Nuevo** — FieldType, TAG_PROFILES, build_meta_fields |
| `bifrost-transfer/src/main.py` | Eliminar FieldType+TAG_PROFILES, import desde meta_fields, refactorizar _build_copy_content y _build_tag_manager_content, actualizar _ws_save |

---

## Fuera de scope

- Añadir nuevos perfiles a `TAG_PROFILES` (eso es cambio de datos, no de lógica).
- Campos de tipo `NUMBER` (ya hay un `pass` en el código actual; se mantiene igual).
- Guardar valores de campos entre cambios de perfil (siempre se borran, con confirmación).
