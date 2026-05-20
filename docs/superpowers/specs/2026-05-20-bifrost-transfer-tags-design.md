# Tag Manager para bifrost-transfer

**Fecha:** 2026-05-20  
**Estado:** Diseño aprobado, pendiente de plan de implementación  
**Apps afectadas:** `bifrost-transfer`

---

## Motivación

Hoy, los usuarios pueden etiquetar los ficheros S3 en el momento de la copia
(los 7 campos de metadatos se pasan como `x-amz-tagging` vía `--header-upload`
en rclone). Pero no hay ninguna herramienta para ver ni modificar los tags de
ficheros ya existentes en MinIO, ni para hacerlo de forma masiva sobre un prefijo
(equivalente a una "carpeta").

El objetivo es añadir una pantalla "Tag Manager" en `bifrost-transfer` donde el
usuario pueda navegar la jerarquía de buckets/carpetas, seleccionar un fichero o
una carpeta, ver los tags actuales y aplicar un tagset nuevo — sin re-subir datos.

---

## Decisiones de diseño

- **API de tags: boto3 directo**, no rclone. `put_object_tagging` y
  `get_object_tagging` son operaciones de metadatos; no re-suben datos y son
  rápidas. boto3 ya está en las dependencias del proyecto.
- **Credenciales:** leídas del `rclone.conf` activo (mismas STS que se acaban de
  renovar en el flujo normal). Nueva función `get_s3_client_from_profile()` en
  backend.
- **Modo de aplicación: replace completo.** S3 permite máximo 10 tags por objeto;
  replace evita acumulación y es más predecible que merge.
- **Sistema de perfiles de tags (`TAG_PROFILES`).** Constante en `main.py` que
  define los conjuntos de campos disponibles. Ahora hay uno solo ("IRB Standard")
  con los 7 campos ya existentes. Diseñado para añadir más perfiles en el futuro
  sin cambiar la UI.
- **Vista dedicada (no drawer/panel).** El editor necesita espacio simultáneo
  para el navegador y la tabla de campos. Un drawer sería demasiado estrecho;
  un modal, incómodo para navegar.
- **Log en pantalla + fichero.** El log de operaciones aparece en la pantalla al
  aplicar tags y se guarda automáticamente en `~/bifrost-logs/` al terminar.
- Esta funcionalidad estará disponible tanto con la verisón desktop como la verisón web.

---

## TAG_PROFILES

Constante a nivel de módulo en `bifrost-transfer/src/main.py`, definida justo
después de las constantes STS:

```python
TAG_PROFILES: dict[str, list[tuple[str, str]]] = {
    "IRB Standard": [
        ("Project",          "project_name"),
        ("Host machine",     "compute_node"),
        ("Sample type",      "sample_type"),
        ("Input data type",  "input_data_type"),
        ("Output data type", "output_data_type"),
        ("Requested by",     "requested_by"),
        ("Research group",   "research_group"),
    ],
}
```

`_build_copy_content` pasa a usar `TAG_PROFILES["IRB Standard"]` en lugar de
su propia lista `meta_labels` inline.

---

## Cambios en `shared/bifrost_backend/backend.py`

Cinco funciones nuevas al final de la sección "GESTIÓN DE PERFILES RCLONE":

### `get_s3_client_from_profile(profile_name, endpoint)`
Lee `access_key_id`, `secret_access_key`, `session_token` del perfil rclone dado
en `rclone.conf` (vía `configparser`) y devuelve un cliente `boto3.client("s3")`
con `endpoint_url=endpoint`.

### `list_prefix_contents(s3_client, bucket, prefix) -> (folders, files)`
Llama a `list_objects_v2` con `Delimiter="/"`. Devuelve:
- `folders`: lista de prefijos (strings terminados en `/`).
- `files`: lista de claves completas de objetos en ese nivel.
Excluye el objeto "carpeta" si existe (clave == prefix).

### `get_object_tags(s3_client, bucket, key) -> dict[str, str]`
Llama a `get_object_tagging` y devuelve el TagSet como dict `key → value`.

### `apply_tags_to_prefix(s3_client, bucket, prefix, tagset, log_fn, on_progress) -> int`
Lista paginada todos los objetos bajo `prefix` (sin delimitador). Aplica
`put_object_tagging` a cada uno con `ThreadPoolExecutor(max_workers=8)`.
Llama a `log_fn(msg)` por cada objeto (éxito ✓ o error ✗) y a
`on_progress(n, total)` tras cada operación. Devuelve el número de objetos
tagueados con éxito.

### `apply_tags_to_object(s3_client, bucket, key, tagset) -> None`
Aplica `put_object_tagging` a un único objeto (para la edición individual de
fichero).

---

## Cambios en `bifrost-transfer/src/main.py`

### Nueva función `_build_tag_manager_content`

Firma:
```python
def _build_tag_manager_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    on_back: Callable,
) -> ft.Control:
```

#### Layout

```
┌──────────────────────────────────────────────────────────────┐
│ ← Back   🏷️ Tag Manager — {perfil_rclone}                    │
├─────────────────────────┬────────────────────────────────────┤
│ BROWSER (w≈380)         │ EDITOR (expand)                    │
│                         │                                    │
│ breadcrumb clickable    │ Profile:  [IRB Standard ▼]         │
│ ─────────────────────   │                                    │
│ 📁 2024/                │ Project         [___________]      │
│   📁 experimento1/      │ Host machine    [___________]      │
│     📁 raw/         ←sel│ Sample type     [___________]      │
│     📄 README.txt       │ ...                                │
│                         │                                    │
│                         │ ┌─────────────────────────────┐   │
│                         │ │ 📁 raw/ — 143 ficheros       │   │
│                         │ │ (tags del primer fichero)    │   │
│                         │ └─────────────────────────────┘   │
│                         │                                    │
│                         │ [Apply tags →]                     │
├─────────────────────────┴────────────────────────────────────┤
│ LOG (oculto hasta primer Apply)                               │
│ ✓ raw/sample1.bam                                            │
│ ✓ raw/sample2.bam  ...                                       │
└──────────────────────────────────────────────────────────────┘
```

#### Estado de navegación

```python
nav = {"bucket": None, "prefix": ""}
# bucket == None  →  vista de lista de buckets
# bucket != None  →  navegando dentro del bucket
```

#### Estado de selección

```python
sel = {
    "type": "none" | "prefix" | "file",
    "key": None,      # clave completa si type=="file"
    "count": 0,       # nº de objetos afectados
    "display": "",    # texto descriptivo para el panel derecho
}
```

#### Reglas de interacción del browser

| Acción | Comportamiento |
|--------|---------------|
| Click en 📁 carpeta | Navegar dentro (actualizar browser, sel.type="prefix", prefill con tags del primer objeto del nivel) |
| Click en 📄 fichero | sel.type="file", cargar tags de ese fichero, prefill editor |
| Click en parte del breadcrumb | Navegar a ese nivel |
| Raíz del breadcrumb | Volver a lista de buckets |

Cuando el usuario navega a una carpeta (o está en un bucket), el panel derecho
muestra siempre la selección activa. Si no hay fichero seleccionado, la selección
activa es la carpeta actual completa ("todos los ficheros aquí").

#### Panel derecho (editor)

- **Selector de perfil** (`ft.Dropdown`): lista `TAG_PROFILES.keys()`. Cambiar
  el perfil recarga los campos (borra valores actuales). Con un solo perfil
  aparece igualmente para dejar la UI preparada para el futuro.
- **Campos de tags**: generados dinámicamente desde el perfil seleccionado
  (`styled_field` como en el formulario de copia).
- **Indicador de target**: texto descriptivo que muestra qué se va a modificar
  ("📁 Todos los ficheros en `raw/` (143 ficheros)" o "📄 `raw/README.txt`").
- **Prefill automático**: al cambiar la selección, se carga en background el
  tagset del objeto relevante (primer objeto del prefijo o el fichero
  seleccionado) y rellena los campos. El usuario puede modificarlos antes de
  aplicar.
- **Botón "Apply tags →"**: deshabilitado mientras el target es "none". Al
  pulsarlo: hace visible el área de log, lanza la operación en un `safe_thread`,
  deshabilita el botón durante la operación, vuelve a habilitarlo al terminar.

#### Área de log

`ft.ListView` con scroll automático, inicialmente oculto. Se hace visible al
pulsar "Apply tags". Muestra línea a línea el progreso (`✓ clave` / `✗ clave:
error`). Al terminar la operación:
1. Línea de resumen: `✅ N ficheros tagueados (M errores)`.
2. Auto-guardado en `~/bifrost-logs/bifrost-tags-YYYY-MM-DD_HH-MM-SS.log`.
3. Línea en el log: `📄 Log guardado en: <path>`.

### Modificar `_build_copy_content`

- Añadir parámetro `on_tags: Callable | None = None`.
- Crear `tags_btn = btn_secondary("🏷️ Tags", on_click=lambda e: on_tags()) if on_tags else None`.
- Añadir al toolbar row: `[back_btn, tags_btn, expiry_badge, expand, renew_btn]`.

### Añadir `go_tags()` y `go_copy()` en `main()`

```python
def go_tags():
    show_screen(_build_tag_manager_content(
        page,
        perfil_rclone=state["perfil_rclone"],
        endpoint=state["endpoint"],
        on_back=go_copy,
    ))
```

`go_copy()` pasa `on_tags=go_tags` a `_build_copy_content`.

---

## Flujo end-to-end

```
Usuario está en la vista de copia
  → pulsa "🏷️ Tags"
      → go_tags()
          → _build_tag_manager_content()
              → lista buckets (boto3 list_buckets, lazy en background)
              → usuario navega: bucket → carpeta → subcarpeta
              → background: cargar tags del primer objeto → prefill editor
              → background: contar objetos → indicador de target
              → usuario ajusta campos
              → pulsa "Apply tags →"
                  → safe_thread: apply_tags_to_prefix / apply_tags_to_object
                  → log en pantalla línea a línea
                  → al terminar: resumen + autosave log
              → usuario pulsa "← Back" → go_copy() (vista de copia)
```

---

## Fuera de alcance

- Modo merge (añadir/modificar tags sin borrar los existentes): siempre replace.
- Edición de tags libres (key/value custom fuera de los perfiles): los perfiles
  cubren el caso de uso actual.
- Crear/eliminar buckets desde la UI.
- Mostrar el tamaño o fecha de modificación de los objetos en el browser.
- Paginación explícita del browser: `list_objects_v2` ya pagina internamente;
  mostramos todos los resultados del nivel actual.
- Navegar fuera del bucket seleccionado durante la misma sesión (se puede volver
  a la lista de buckets desde el breadcrumb).

---

## Tests

No hay suite automatizada. Validación manual:

1. Navegar a un bucket → subcarpeta → ver prefill de tags del primer objeto.
2. Seleccionar un fichero → ver sus tags en el editor.
3. Editar campos → Apply → verificar log en pantalla y fichero `~/bifrost-logs/`.
4. Verificar con un cliente S3 externo (e.g., MinIO Console) que los tags se han
   aplicado correctamente.
5. Apply a una carpeta con >100 objetos → verificar progreso y resumen correcto.
6. Credenciales expiradas → verificar error claro (boto3 levantará `ClientError`).
7. Sin ficheros bajo el prefijo → botón Apply deshabilitado.

---

## Archivos a modificar

- `shared/bifrost_backend/backend.py` — 5 funciones nuevas.
- `bifrost-transfer/src/main.py` — `TAG_PROFILES` constante, `meta_labels`
  refactorizado, `_build_tag_manager_content` nueva función, `on_tags` en
  `_build_copy_content`, `go_tags` y `go_copy` actualizados.
- `docs/wiki/log.md` — entrada al cerrar la tarea.
