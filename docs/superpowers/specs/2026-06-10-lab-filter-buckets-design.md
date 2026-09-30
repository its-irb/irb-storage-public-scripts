# Diseño: Filtro de laboratorio en browser de buckets

**Fecha:** 2026-06-10  
**Rama:** feature/profiles-copy  
**Alcance:** bifrost-transfer (vista de copia + Tag Manager)

---

## Resumen

Añadir un widget de filtro por laboratorio encima de la lista de buckets en dos lugares:
- El browser de destino de la vista de copia (`build_rclone_browser`)
- El browser del Tag Manager (inline en `_build_tag_manager_content`)

El filtro lee el tag S3 `acronym` de cada bucket bajo demanda (solo cuando el usuario activa el filtro) y muestra únicamente los buckets cuyo acrónimo coincide con el lab seleccionado.

---

## Usuarios objetivo

Core facilities del IRB que gestionan múltiples buckets y necesitan localizarlos rápidamente por laboratorio. El flujo habitual (usuarios normales sin filtro) no incurre ningún coste adicional.

---

## Sección 1: Datos — `LAB_ACRONYMS` en `meta_fields.py`

Nueva constante en `bifrost-transfer/src/meta_fields.py`:

```python
LAB_ACRONYMS: dict[str, str] = {
    "adm":    "Administration",
    "sbnb":   "Nuria López-Bigas",
    "batlle": "Eduard Batlle",
    # ... resto de labs (a rellenar con valores reales)
}
```

- **Clave:** acrónimo exacto que aparece en el tag S3 `acronym` del bucket
- **Valor:** nombre legible que ve el usuario en el dropdown
- **Fuente:** misma lista de PIs del perfil Histopathology, con acrónimos añadidos
- El orden del dict determina el orden de aparición en el filtro

---

## Sección 2: Backend — `get_bucket_tags` en `backend.py`

Nueva función en `shared/bifrost_backend/backend.py`:

```python
def get_bucket_tags(s3_client, bucket: str) -> dict[str, str]:
    """Devuelve los tags del bucket como dict key→value. Vacío si no hay tags."""
    try:
        resp = s3_client.get_bucket_tagging(Bucket=bucket)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    except Exception:
        return {}
```

Maneja `NoSuchTagSet` (bucket sin tags) y cualquier error de red con `except` genérico, consistente con el patrón del resto de funciones de tags.

---

## Sección 3: Widget de filtro — `build_lab_filter_widget` en `meta_fields.py`

```python
def build_lab_filter_widget(
    page: ft.Page,
    on_select: Callable[[str | None], None],
) -> tuple[ft.Control, Callable]:
    ...
```

Devuelve `(widget, clear_fn)`.

### UX

- `TextField` con hint `"Filter by lab…"`
- Al escribir, aparece debajo una lista que filtra en tiempo real por acrónimo Y por nombre legible
- Al seleccionar un lab: el TextField muestra `"Nuria López-Bigas (sbnb)"`, la lista se cierra, se llama `on_select(acronym)`
- Botón ✕ al lado del TextField para limpiar → llama `on_select(None)`
- Lista visible solo cuando el TextField tiene foco o hay texto
- Si no hay coincidencias: muestra "No results"

### Implementación interna

- Lista de sugerencias como `ft.Column` con `ft.Container` clicables, visible/oculta según estado del TextField
- `clear_fn()` resetea el widget al estado inicial (TextField vacío, lista oculta)

---

## Sección 4: Integración

### 4a. Browser de copia — `build_rclone_browser`

Nuevos parámetros opcionales:
```python
lab_filter_enabled: bool = False
endpoint: str | None = None
```

Cuando `lab_filter_enabled=True`:

1. Se crea el widget de filtro con `build_lab_filter_widget`; se coloca encima de `folder_col` y solo es visible cuando `nav_state["current_path"] == ""` (nivel raíz = lista de buckets)
2. El callback `on_select(acronym)` guarda el acrónimo en `filter_state = {"acronym": None}` y llama `_navigate("")` para recargar
3. En `_navigate("")` (carga de buckets), si `filter_state["acronym"]` tiene valor:
   - Crea cliente boto3 con `get_s3_client_from_profile(perfil, endpoint)`
   - Llama `get_bucket_tags` para cada bucket en paralelo (`ThreadPoolExecutor`)
   - Muestra solo los buckets donde `tags.get("acronym") == filter_state["acronym"]`
4. Si no hay filtro activo, comportamiento actual sin cambios

El call site en `_build_copy_content` pasa `lab_filter_enabled=True, endpoint=endpoint`.

### 4b. Browser del Tag Manager — inline en `_build_tag_manager_content`

El Tag Manager ya dispone de `endpoint` y `_get_client()`. Se añade:

1. El widget de filtro encima de `browser_col`
2. `filter_state = {"acronym": None}` local
3. En `_refresh()` (carga de buckets al nivel raíz), misma lógica: si hay acrónimo activo, fetch paralelo de tags y filtrado antes de renderizar

### Paralelismo en fetch de tags

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def _fetch_tags_parallel(client, bucket_names):
    results = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(get_bucket_tags, client, b): b for b in bucket_names}
        for f in as_completed(futures):
            results[futures[f]] = f.result()
    return results
```

El spinner de "Loading…" ya existente cubre la espera.

---

## Flujo completo (caso de uso)

1. Usuario abre browser de buckets (copia o Tag Manager)
2. Ve el campo "Filter by lab…" encima de la lista
3. Escribe "Bat" → aparecen sugerencias → selecciona "Eduard Batlle (batlle)"
4. Spinner mientras se leen los tags de todos los buckets en paralelo
5. Lista se actualiza mostrando solo los buckets con `acronym=batlle`
6. Usuario navega dentro de uno de esos buckets (el filtro desaparece — ya no estamos en el root)
7. Pulsa ✕ → vuelven todos los buckets

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | Añadir `LAB_ACRONYMS`, `build_lab_filter_widget` |
| `shared/bifrost_backend/backend.py` | Añadir `get_bucket_tags` |
| `bifrost-transfer/src/main.py` | Integrar filtro en `build_rclone_browser` y `_build_tag_manager_content` |

---

## Restricciones y gotchas

- `build_lab_filter_widget` importa de `bifrost_frontend.frontend` (paleta de colores) — consistente con el patrón de `meta_fields.py`
- El filtro solo aplica al nivel raíz (bucket list); al navegar dentro de un bucket no tiene efecto
- Los tags de bucket se leen bajo demanda; no se cachean entre sesiones
- `get_bucket_tags` con `except Exception` silencia errores — un bucket inaccesible simplemente no mostrará el tag (quedará fuera del filtro aunque tenga el acrónimo correcto)
- Thread-safety: el fetch paralelo ocurre en un hilo de background; el render final usa `backend.ui_call(page, fn)`
