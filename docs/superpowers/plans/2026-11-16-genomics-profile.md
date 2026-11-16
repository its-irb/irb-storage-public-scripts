# Perfil de metadatos "Genomics" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir el perfil de tags S3 "Genomics" con campos obligatorios, validación unificada de caracteres y longitud, y autodetección de perfil por `provider`.

**Architecture:** Todo el modelo de perfiles vive en `bifrost-transfer/src/meta_fields.py` (`TAG_PROFILES`, `build_meta_fields`, `detect_profile`, validación). Las vistas `views/copy.py` y `views/tag_manager.py` solo iteran sobre `TAG_PROFILES` y llaman a `validate_tagset` al pulsar Copy o Aplicar. Se centraliza la validación en `check_tag_value` y se añade un 7º elemento `required` a las tuplas de campo sin romper los perfiles existentes.

**Tech Stack:** Python 3, Flet, pytest (nuevo, solo para la lógica pura de `meta_fields.py`).

**Spec:** `docs/superpowers/specs/2026-11-16-genomics-profile-design.md`

## Global Constraints

- Límites de S3: key de 128 caracteres como máximo, valor de 256 como máximo; 10 tags por objeto como máximo (Genomics tiene 9 campos).
- Caracteres permitidos en keys y valores: el regex existente `_TAG_VALUE_RE = ^[\w\s.:/=+\-@]*$` (unicode). No admite apóstrofes, paréntesis, comas ni comillas.
- Los multiselect y multifreetext guardan el valor uniendo con `:` las opciones ordenadas (`":".join(sorted(...))`).
- Valores de `provider`: Histopathology = `Histopathology IRB Core Facility`; Genomics = `Advanced Genomic Technologies IRB Core Facility`.
- Opciones saneadas (sin `'` ni paréntesis): `scRNA-seq 3prime`, `scRNA-seq 5prime/VDJ`, `10x GEM-X 3prime`, `SMART-Seq Total RNA Takara`, `Qubit+Tapestation`, `DNA purification`.
- Los perfiles "IRB Standard" e "Histopathology" no cambian de comportamiento visible (sin `*`, sin bloqueos nuevos).
- No añadir contenido a `CLAUDE.md` (está marcado "Moved"); la documentación va en `docs/agent/`, `docs/development/` y `docs/wiki/`.
- Mensajes de commit en español, formato `tipo(ámbito): descripción`, como el historial del repo.
- Trabajar en la rama `feature/genomics-profile`.

## Review Focus

1. Valor de exactamente 256 caracteres válido y de 257 inválido; key de 128 válida y de 129 inválida (Task 1).
2. Application con las 26 opciones juntas (355 caracteres): la opción que supere 256 no se añade y se ve el error inline (Task 4, comprobación manual).
3. Campo obligatorio ausente del diccionario o vacío cuenta como faltante; uno relleno no (Task 2).
4. Objeto con `provider` de Genomics y un tag extra que no es de ningún perfil se detecta como Genomics (Task 3).
5. Objeto Histopathology antiguo sin `provider`, y objeto con `provider` desconocido, siguen detectándose por subconjunto de keys (Task 3).

---

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | Constantes y validación, `TAG_PROFILES`, `build_meta_fields`, `missing_required`, `detect_profile` |
| `bifrost-transfer/src/views/copy.py` | Bloquea Copy si faltan obligatorios |
| `bifrost-transfer/src/views/tag_manager.py` | Bloquea Aplicar si faltan obligatorios; `max_length` leyendo constantes |
| `bifrost-transfer/tests/conftest.py` (nuevo) | Pone `src/` en `sys.path` |
| `bifrost-transfer/tests/test_meta_fields.py` (nuevo) | Tests de lógica pura |

Comando de tests (desde `bifrost-transfer/`): `uv run --no-sync --with pytest python -m pytest tests -v`. Si `bifrost_frontend` no se importa, activar antes el `.venv` de `bifrost-transfer`.

---

### Task 1: Validación unificada de caracteres y longitud

**Files:**
- Create: `bifrost-transfer/tests/conftest.py`, `bifrost-transfer/tests/test_meta_fields.py`
- Modify: `bifrost-transfer/src/meta_fields.py` (`_validate_tag_value`, `check_tag_value`, `validate_tagset`), `bifrost-transfer/src/views/tag_manager.py` (`_build_file_editor_row`)

**Interfaces:**
- Produces: `TAG_KEY_MAX: int = 128`, `TAG_VALUE_MAX: int = 256`, `check_tag_value(text: str, max_len: int = TAG_VALUE_MAX) -> str | None` (mensaje de error o `None`), `validate_tagset(tags: dict[str, str]) -> list[str]` (misma firma que hoy).

- [ ] **Step 1: Crear `tests/conftest.py`** que inserte `bifrost-transfer/src` en `sys.path`.

- [ ] **Step 2: Escribir los tests fallidos** en `tests/test_meta_fields.py`:

```python
def test_value_length_boundary():
    assert check_tag_value("a" * 256) is None
    assert check_tag_value("a" * 257) is not None

def test_key_length_boundary():
    assert check_tag_value("k" * 128, TAG_KEY_MAX) is None
    assert check_tag_value("k" * 129, TAG_KEY_MAX) is not None

def test_invalid_characters_rejected():
    for bad in ["scRNA-seq 3'", "Takara (x)", "a,b", 'a"b']:
        assert check_tag_value(bad) is not None
    assert check_tag_value("") is None

def test_validate_tagset_reports_key_and_value():
    errs = validate_tagset({"k" * 129: "ok", "good": "v" * 257, "x": "ok"})
    assert len(errs) == 2
    assert any("good" in e for e in errs)
```

- [ ] **Step 3: Ejecutar los tests y comprobar que fallan** (`ImportError` de `TAG_KEY_MAX`).

- [ ] **Step 4: Implementar en `meta_fields.py`:** constantes; `check_tag_value` comprueba primero caracteres (mensaje `_TAG_VALUE_ERROR` existente) y luego longitud (`f"Maximum {max_len} characters ({len(text)} entered)"`); `validate_tagset` llama a `check_tag_value(k, TAG_KEY_MAX)` y `check_tag_value(v)` y prefija con `Key «{k}»: ` / `Field «{k}»: `; `_validate_tag_value` delega en `check_tag_value` en lugar de usar el regex directamente.

- [ ] **Step 5: Ejecutar los tests y comprobar que pasan.**

- [ ] **Step 6: En `tag_manager.py`**, importar `TAG_KEY_MAX, TAG_VALUE_MAX` y usarlos como `max_length` de los dos `TextField` (key y value); en `on_key_change` llamar a `check_tag_value(key_tf.value or "", TAG_KEY_MAX)`.

- [ ] **Step 7: Commit**

```bash
git add bifrost-transfer/tests bifrost-transfer/src/meta_fields.py bifrost-transfer/src/views/tag_manager.py
git commit -m "refactor(tags): unifica la validación de caracteres y longitud en check_tag_value"
```

---

### Task 2: Campos obligatorios (`required`)

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (`build_meta_fields`, nueva `missing_required`), `bifrost-transfer/src/views/copy.py` (`do_copy`), `bifrost-transfer/src/views/tag_manager.py` (`do_apply`, `_on_save_file_tags`)
- Test: `bifrost-transfer/tests/test_meta_fields.py`

**Interfaces:**
- Consumes: `TAG_PROFILES`, `validate_tagset` (Task 1).
- Produces: tuplas de campo con 7º elemento opcional `required: bool` (ausente = `False`); `missing_required(profile_name: str, values: dict[str, str]) -> list[str]` devuelve los labels (sin `*`) de los campos `required` vacíos o ausentes.

- [ ] **Step 1: Escribir el test fallido.** Monkeypatchear `TAG_PROFILES` con un perfil de prueba de dos campos (`("A", "a", FieldType.TEXT, False, None, None, True)` y `("B", "b", FieldType.TEXT, False, None, None)`):

```python
def test_missing_required(monkeypatch):
    monkeypatch.setitem(TAG_PROFILES, "T", [A_REQUIRED, B_OPTIONAL])
    assert missing_required("T", {"a": "", "b": ""}) == ["A"]
    assert missing_required("T", {"b": "x"}) == ["A"]      # ausente
    assert missing_required("T", {"a": "x", "b": ""}) == []
```

- [ ] **Step 2: Ejecutar el test y comprobar que falla** (`ImportError`).

- [ ] **Step 3: Implementar `missing_required`** en `meta_fields.py`; en `build_meta_fields` leer `required = item[6] if len(item) > 6 else False` y usar un `shown_label` con ` *` añadido cuando sea `True` en los cinco sitios que pintan el label (uniselect, multiselect, multifreetext, date y `styled_field(label)` del TEXT).

- [ ] **Step 4: Ejecutar el test y comprobar que pasa.**

- [ ] **Step 5: Enforcement.** En `copy.py` `do_copy`, tras el bloque de `validate_tagset`: `missing = missing_required(active_copy_profile["name"], metadatos)`; si hay, `show_dialog(page, "Missing required fields", ", ".join(missing), C_ERROR)` y `return`. En `tag_manager.py`, lo mismo en `do_apply` con `active_profile["name"]` y en `_on_save_file_tags` solo cuando `file_editor_mode["mode"] == "profile"`. No tocar el editor manual de key/value. Importar `missing_required` en ambos ficheros.

- [ ] **Step 6: Verificación manual:** con "IRB Standard" e "Histopathology" no aparece `*` ni diálogo nuevo.

- [ ] **Step 7: Commit**

```bash
git add bifrost-transfer/src bifrost-transfer/tests
git commit -m "feat(tags): añade el flag required a los campos de perfil y bloquea Copy/Aplicar si faltan"
```

---

### Task 3: Perfil Genomics, `provider` fijo y detección por `provider`

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (`TAG_PROFILES`, `build_meta_fields` rama UNISELECT, `detect_profile`)
- Test: `bifrost-transfer/tests/test_meta_fields.py`

**Interfaces:**
- Consumes: `check_tag_value`, tuplas con `required` (Tasks 1 y 2).
- Produces: `TAG_PROFILES["Genomics"]` con las keys `owner, users, date, provider, application, library_kit, species, sample_type, comments`; `detect_profile(tags: dict[str, str]) -> str | None` mira primero `provider`.

- [ ] **Step 1: Escribir los tests fallidos:**

```python
GENOMICS_PROVIDER = "Advanced Genomic Technologies IRB Core Facility"
HISTO_PROVIDER = "Histopathology IRB Core Facility"

def test_genomics_profile_shape():
    keys = [f[1] for f in TAG_PROFILES["Genomics"]]
    assert keys == ["owner","users","date","provider","application",
                    "library_kit","species","sample_type","comments"]
    required = {f[1] for f in TAG_PROFILES["Genomics"] if len(f) > 6 and f[6]}
    assert required == set(keys) - {"comments"}

def test_genomics_options_are_valid_s3_values():
    for f in TAG_PROFILES["Genomics"]:
        for opt in (f[4] or []):
            value = opt[0] if isinstance(opt, tuple) else opt
            assert check_tag_value(value) is None, (f[1], value)

def test_application_all_joined_exceeds_limit():
    app = next(f for f in TAG_PROFILES["Genomics"] if f[1] == "application")[4]
    assert len(app) == 26
    assert check_tag_value(":".join(sorted(app))) is not None

def test_detect_by_provider_with_shared_keys_only():
    common = {"owner":"bbg","users":"u","date":"2026-01-01","species":"human","sample_type":"RNA"}
    assert detect_profile({**common, "provider": GENOMICS_PROVIDER}) == "Genomics"
    assert detect_profile({**common, "provider": HISTO_PROVIDER}) == "Histopathology"

def test_detect_genomics_with_extra_tag():
    assert detect_profile({"provider": GENOMICS_PROVIDER, "custom_tag": "x"}) == "Genomics"

def test_detect_falls_back_to_keys():
    assert detect_profile({"instrument": "Phenoimager"}) == "Histopathology"   # sin provider
    assert detect_profile({"provider": "Other", "instrument": "Nanozoomer"}) == "Histopathology"
    assert detect_profile({"project_name": "p"}) == "IRB Standard"
    assert detect_profile({}) is None
```

- [ ] **Step 2: Ejecutar los tests y comprobar que fallan** (`KeyError: 'Genomics'`).

- [ ] **Step 3: Añadir el perfil `"Genomics"`** a `TAG_PROFILES` con las tuplas del spec (todas `required=True` salvo `comments`; `allow_custom=False` en todos los selects; `comments` es TEXT con helper `"Incidents, QC deviations, notes"`; `date` DATE; `users` MULTIFREETEXT). Opciones de Application y Library Kit exactamente como en el spec, ya saneadas. Para no duplicar con Histopathology, extraer a constantes de módulo `_OWNER_OPTIONS` (la lista `(acr, f"{name} ({acr})")` ordenada por nombre) y `_USERS_HELPER` (el texto de ayuda de `users`) y usarlas en ambos perfiles.

- [ ] **Step 4: Ejecutar los tests de forma y opciones** (`shape`, `options_are_valid`, `all_joined`) y comprobar que pasan.

- [ ] **Step 5: `provider` fijo.** En la rama UNISELECT de `build_meta_fields`, cuando `_single` sea `True`, poner `dd.disabled = True`.

- [ ] **Step 6: Reescribir `detect_profile`:** si `tags.get("provider")` coincide con alguna opción del campo `provider` de un perfil (mapa derivado de `TAG_PROFILES`, sin tabla aparte), devolver ese perfil; si no, aplicar la lógica actual de subconjunto de keys sin cambios.

- [ ] **Step 7: Ejecutar toda la suite y comprobar que pasa.**

- [ ] **Step 8: Verificación manual** (`uv run flet run` del `bifrost-transfer`, con el venv de la app): "Genomics" aparece en los selectores de Copy y Tag Manager, con `*` en los obligatorios, y Provider aparece bloqueado y ya relleno. Con Genomics seleccionado, Copy con campos vacíos muestra "Missing required fields" con los labels.

- [ ] **Step 9: Commit**

```bash
git add bifrost-transfer/src/meta_fields.py bifrost-transfer/tests
git commit -m "feat(tags): añade el perfil Genomics y detecta el perfil por provider"
```

---

### Task 4: Límite de longitud inline en multiselect y multifreetext

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (ramas MULTISELECT y MULTIFREETEXT de `build_meta_fields`)

**Interfaces:**
- Consumes: `check_tag_value` (Task 1). Sin interfaz nueva (cambio de UI, sin test unitario: la lógica de validación ya está cubierta en Tasks 1 y 3).

- [ ] **Step 1: MULTISELECT.** Crear siempre un `ft.Text` de error (hoy solo existe con `allow_custom`) debajo de los chips. En `_on_select`, antes de añadir `val`, calcular `err = check_tag_value(":".join(sorted(sel["s"] | {val})))`; si hay error, no añadir y mostrarlo en ese `Text`; si no, ocultarlo. En `_add_custom`, sustituir el bloque con `_TAG_VALUE_RE.match(val)` por la misma comprobación sobre el valor unido y usar ese mismo `Text` (se elimina `ctf_err`).

- [ ] **Step 2: MULTIFREETEXT.** En `_add`, sustituir `_TAG_VALUE_RE.match(val)` por `check_tag_value(":".join(sorted(sel["s"] | {val})))`, mostrando el error en el `err_txt` existente.

- [ ] **Step 3: Comprobar que ya no queda `_TAG_VALUE_RE.match` fuera de `check_tag_value`** (`Grep` sobre `meta_fields.py`).

- [ ] **Step 4: Verificación manual:** con Genomics, añadir opciones de Application hasta que las unidas pasen de 256 caracteres: la que lo supere no se añade y sale el error en rojo; quitar un chip y volver a añadir funciona. Con Histopathology (`users` multifreetext), añadir un usuario con carácter prohibido sigue mostrando el error de caracteres.

- [ ] **Step 5: Commit**

```bash
git add bifrost-transfer/src/meta_fields.py
git commit -m "feat(tags): avisa inline al superar 256 caracteres en multiselect y multifreetext"
```

---

### Task 5: Documentación y log

**Files:**
- Modify: `docs/agent/`, `docs/development/` (lo que proponga `docs-update`), `docs/wiki/log.md`

- [ ] **Step 1: Ejecutar el skill `docs-update`** y aplicar solo los cambios que el usuario confirme (describir `TAG_PROFILES` con 7º elemento `required`, `check_tag_value`/`validate_tagset`, `detect_profile` por `provider` y el nuevo perfil).

- [ ] **Step 2: Añadir una entrada en `docs/wiki/log.md`** con las decisiones: valores saneados (sin `'` ni paréntesis), flag `required`, validación unificada con límites 128/256, y `provider` como criterio de detección.

- [ ] **Step 3: Commit**

```bash
git add docs
git commit -m "docs(tags): documenta el perfil Genomics, el flag required y la validación unificada"
```

---

## Self-Review

- **Cobertura del spec:** §1 perfil → Task 3; §2 obligatorios → Task 2; §3 validación unificada → Tasks 1 y 4 (incluye `max_length` en UI con constantes); §4 `detect_profile` y `provider` fijo → Task 3; §5 documentación → Task 5; Notas (separador `:`, 10 tags) → Global Constraints.
- **Consistencia de tipos:** `check_tag_value(text, max_len)`, `TAG_KEY_MAX`, `TAG_VALUE_MAX`, `missing_required(profile_name, values)` y `detect_profile(tags)` se nombran igual en todas las tareas.
- **Orden:** Task 2 antes que Task 3 porque Genomics usa el 7º elemento de las tuplas; Task 1 antes que 3 y 4 porque ambas llaman a `check_tag_value`.
