# Perfil de metadatos "Genomics" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir el perfil de tags S3 "Genomics" con campos obligatorios, validación unificada de caracteres y longitud, y perfiles cuyo nombre es el valor de su tag `provider` (también usado para autodetectarlos).

**Architecture:** Todo el modelo de perfiles vive en `bifrost-transfer/src/meta_fields.py` (`TAG_PROFILES`, `build_meta_fields`, `detect_profile`, validación). Las vistas `views/copy.py` y `views/tag_manager.py` solo iteran sobre `TAG_PROFILES` y, al pulsar Copy o Aplicar, hacen una única llamada a `validate_profile_tagset` (formato, longitud y obligatorios, un solo diálogo). El campo `provider` no se declara en cada perfil: lo añade `profile_fields(name)` con el nombre del perfil como único valor, `build_meta_fields` lo fuerza siempre a ese valor (ignora el `provider` del prefill) y `detect_profile` lo usa como criterio principal. Se centraliza la validación en `check_tag_value` y se añade un 7º elemento `required` a las tuplas de campo sin romper los perfiles existentes.

**Tech Stack:** Python 3, Flet, pytest (nuevo, solo para la lógica pura de `meta_fields.py`).

**Spec:** `docs/superpowers/specs/2026-11-16-genomics-profile-design.md`

## Global Constraints

- Límites de S3: key de 128 caracteres como máximo, valor de 256 como máximo; 10 tags por objeto como máximo (con el `provider` automático: IRB Standard 8, Genomics 9, Histopathology 10).
- Caracteres permitidos en keys y valores: el regex existente `_TAG_VALUE_RE = ^[\w\s.:/=+\-@]*$` (unicode). No admite apóstrofes, paréntesis, comas ni comillas. Los nombres de perfil también son tags, así que deben cumplirlo.
- Los multiselect y multifreetext guardan el valor uniendo con `:` las opciones ordenadas (`":".join(sorted(...))`).
- Nombres de perfil = valor de `provider`: `IRB Standard`, `Histopathology IRB Core Facility` (antes `Histopathology`), `Advanced Genomic Technologies IRB Core Facility`.
- Opciones saneadas (sin `'` ni paréntesis): `scRNA-seq 3prime`, `scRNA-seq 5prime/VDJ`, `10x GEM-X 3prime`, `SMART-Seq Total RNA Takara`, `Qubit+Tapestation`, `DNA purification`.
- IRB Standard conserva sus 7 campos tal cual están en el working tree (`project_name`, `compute_node`, `sample_type`, `input_data_type`, `output_data_type`, `requested_by`, `research_group`) y su nombre; solo gana el tag `provider`. No se tocan en este plan.
- Una sola función de validación para las vistas: `validate_profile_tagset`. `validate_tagset` y `missing_required` son piezas internas; las vistas no las llaman por separado.
- La validación de longitud total (256) se hace solo en `validate_profile_tagset` al pulsar Copy o Aplicar. El inline de multiselect y multifreetext solo comprueba caracteres de cada opción con `check_tag_value`, sin bloqueo por longitud.
- Fuera del alcance: la coma que falta tras `"adm"` en `WORM_FACILITY_DATA_SUBFOLDERS` (`meta_fields.py:97`, concatena `"admbiostats"`). Se corrige aparte, en su propio commit.
- No añadir contenido a `CLAUDE.md` (está marcado "Moved"); la documentación va en `docs/agent/`, `docs/development/`, `docs/user/`, `README.md` y `docs/wiki/`.
- Mensajes de commit en español, formato `tipo(ámbito): descripción`, como el historial del repo.
- Trabajar en la rama `feature/genomics-profile`.

## Review Focus

1. Valor de exactamente 256 caracteres válido y de 257 inválido; key de 128 válida y de 129 inválida (Task 1).
2. Objeto con solo las keys comunes entre perfiles (owner, users, date, species, sample_type) más su `provider`: el perfil lo decide `provider`, no el orden (Tasks 2 y 4).
3. Objetos antiguos sin `provider` (IRB Standard e Histopathology antiguos) y objetos con un `provider` desconocido siguen detectándose por keys; `{}` devuelve `None` (Task 2).
4. Campo obligatorio ausente del diccionario o vacío cuenta como faltante; uno relleno no (Task 3).
5. Application con las 26 opciones juntas supera 256 caracteres: `validate_profile_tagset` lo rechaza al pulsar Copy o Aplicar y nombra el campo (Tasks 3 y 4).
6. Un objeto detectado por fallback con un `provider` desconocido se abre con el provider forzado al nombre del perfil, no con el valor antiguo (Task 2).
7. Las vistas llaman solo a `validate_profile_tagset`, no a `validate_tagset` ni a `missing_required` (Task 3).

---

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | Constantes y validación, `TAG_PROFILES`, `profile_fields`, `build_meta_fields`, `missing_required` (interna), `validate_profile_tagset`, `detect_profile` |
| `bifrost-transfer/src/views/copy.py` | Una llamada a `validate_profile_tagset` en Copy; ancho del desplegable de perfil |
| `bifrost-transfer/src/views/tag_manager.py` | Una llamada a `validate_profile_tagset` en Aplicar; `max_length` leyendo constantes; ancho de los desplegables de perfil |
| `bifrost-transfer/tests/conftest.py` (nuevo) | Pone `src/` en `sys.path` |
| `bifrost-transfer/tests/test_meta_fields.py` (nuevo) | Tests de lógica pura |

Comando de tests (desde `bifrost-transfer/`): `uv run --no-sync --with pytest python -m pytest tests -v`. Si `bifrost_frontend` no se importa, activar antes el `.venv` de `bifrost-transfer`.

---

### Task 1: Validación unificada de caracteres y longitud

**Files:**
- Create: `bifrost-transfer/tests/conftest.py`, `bifrost-transfer/tests/test_meta_fields.py`
- Modify: `bifrost-transfer/src/meta_fields.py` (`_validate_tag_value`, `check_tag_value`, `validate_tagset`, ramas multiselect y multifreetext de `build_meta_fields`), `bifrost-transfer/src/views/tag_manager.py` (`_build_file_editor_row`)

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

- [ ] **Step 7: Eliminar las copias inline del regex en `build_meta_fields`** (multiselect `_add_custom` y multifreetext `_add`): sustituir `_TAG_VALUE_RE.match(val)` por `err = check_tag_value(val)` y mostrar `err` en el `Text` de error que ya existe. Es solo comprobación de caracteres de cada opción; la longitud del valor unido la valida `validate_profile_tagset` al pulsar Copy o Aplicar (Task 3). No se crean controles nuevos ni se bloquea por longitud al añadir.

- [ ] **Step 8: Comprobar que ya no queda `_TAG_VALUE_RE.match` fuera de `check_tag_value`** (`Grep` sobre `meta_fields.py`).

- [ ] **Step 9: Commit**

```bash
git add bifrost-transfer/tests bifrost-transfer/src/meta_fields.py bifrost-transfer/src/views/tag_manager.py
git commit -m "refactor(tags): unifica la validación de caracteres y longitud en check_tag_value"
```

---

### Task 2: El nombre del perfil es el valor de `provider`

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (`TAG_PROFILES`, nueva `profile_fields`, `build_meta_fields`, `detect_profile`), `bifrost-transfer/src/views/copy.py` (desplegable `profile_dd`), `bifrost-transfer/src/views/tag_manager.py` (`profile_dd` y `prefill_profile_dd`)
- Test: `bifrost-transfer/tests/test_meta_fields.py`

**Interfaces:**
- Consumes: `check_tag_value` (Task 1).
- Produces: `profile_fields(profile_name: str) -> list[tuple]` (provider bloqueado primero + los campos del perfil); `apply_provider(profile_name: str, values: dict[str, str]) -> dict[str, str]`; `detect_profile(tags: dict[str, str]) -> str | None`; la clave `"Histopathology"` de `TAG_PROFILES` pasa a ser `"Histopathology IRB Core Facility"`. Constantes de test: `IRB = "IRB Standard"`, `HISTO = "Histopathology IRB Core Facility"`.

- [ ] **Step 1: Escribir los tests fallidos:**

```python
COMMON = {"owner": "bbg", "users": "u", "date": "2026-01-01", "species": "human", "sample_type": "RNA"}

@pytest.mark.parametrize("name", list(TAG_PROFILES))
def test_profile_name_is_valid_tag_value(name):
    assert check_tag_value(name) is None

@pytest.mark.parametrize("name", list(TAG_PROFILES))
def test_provider_is_automatic_and_locked_to_name(name):
    assert "provider" not in [f[1] for f in TAG_PROFILES[name]]
    first = profile_fields(name)[0]
    assert first[1] == "provider" and first[4] == [name]

def test_detect_by_provider_ignores_key_order():
    assert detect_profile({**COMMON, "provider": HISTO}) == HISTO
    assert detect_profile({"project_name": "p", "provider": IRB}) == IRB

def test_detect_falls_back_to_keys():
    assert detect_profile({"instrument": "Phenoimager"}) == HISTO      # antiguo sin provider
    assert detect_profile({"project_name": "p"}) == IRB                # antiguo sin provider
    assert detect_profile({"provider": "Unknown", "instrument": "Nanozoomer"}) == HISTO
    assert detect_profile({}) is None
```

La lógica de prefill del provider se extrae a una función pura para poder testearla sin Flet:

```python
def test_prefill_forces_provider_to_profile_name():
    assert apply_provider(HISTO, {"provider": "Unknown", "instrument": "Nanozoomer"}) == \
        {"provider": HISTO, "instrument": "Nanozoomer"}
    assert apply_provider(IRB, {"project_name": "p"}) == {"project_name": "p", "provider": IRB}
```

- [ ] **Step 2: Ejecutar los tests y comprobar que fallan** (`ImportError` de `profile_fields`).

- [ ] **Step 3: Implementar `profile_fields(profile_name: str) -> list[tuple]`** en `meta_fields.py`: `[("Provider", "provider", FieldType.UNISELECT, False, [profile_name], None, True)] + TAG_PROFILES[profile_name]`. La tupla ya lleva el 7º elemento `required` que formaliza la Task 3; hasta entonces `build_meta_fields` lo ignora.

- [ ] **Step 4: Cambiar `TAG_PROFILES`:** renombrar la clave `"Histopathology"` a `"Histopathology IRB Core Facility"` y quitar su tupla `Provider` (las demás tuplas no cambian). IRB Standard no cambia sus tuplas.

- [ ] **Step 5: En `build_meta_fields`**, iterar `profile_fields(profile_name)` en lugar de `TAG_PROFILES[profile_name]` y, en la rama UNISELECT, poner `dd.disabled = True` cuando `_single` sea `True`. Al empezar, `_pre = apply_provider(profile_name, prefill_values or {})`, con `apply_provider(profile_name, values) -> dict` (nueva en `meta_fields.py`, devuelve una copia con `provider = profile_name`). Así un objeto detectado por fallback con un provider antiguo o desconocido se abre con el provider del perfil, nunca como opción extra `valor *`, y se corrige al guardar. Actualizar el docstring.

- [ ] **Step 6: Reescribir `detect_profile`:** si `tags.get("provider")` es una clave de `TAG_PROFILES`, devolverla; si no, aplicar la lógica actual de subconjunto de keys sobre `{f[1] for f in profile_fields(name)}`. Actualizar el docstring.

- [ ] **Step 7: Ejecutar toda la suite y comprobar que pasa.**

- [ ] **Step 8: Anchos de los desplegables.** El nombre más largo mide 47 caracteres: ensanchar `profile_dd` y `prefill_profile_dd` de `tag_manager.py` (hoy `width=220`) y `profile_dd` de `copy.py` hasta que el nombre completo se lea sin recortar.

- [ ] **Step 9: Verificación manual** (`uv run flet run` en `bifrost-transfer`, con el venv de la app): en Copy y Tag Manager, IRB Standard e Histopathology IRB Core Facility aparecen con el nombre legible y Provider sale primero, bloqueado y relleno con el nombre del perfil. Abrir un objeto Histopathology ya etiquetado lo detecta por su provider. Abrir uno con `provider` desconocido detectado por keys muestra el provider del perfil, bloqueado.

- [ ] **Step 10: Commit**

```bash
git add bifrost-transfer/src bifrost-transfer/tests
git commit -m "feat(tags): el nombre del perfil es el valor de provider y detect_profile lo usa"
```

---

### Task 3: Campos obligatorios (`required`)

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (`build_meta_fields`, nuevas `missing_required` y `validate_profile_tagset`), `bifrost-transfer/src/views/copy.py` (`do_copy`), `bifrost-transfer/src/views/tag_manager.py` (`do_apply`, `_on_save_file_tags`)
- Test: `bifrost-transfer/tests/test_meta_fields.py`

**Interfaces:**
- Consumes: `TAG_PROFILES`, `profile_fields` (Task 2), `validate_tagset` (Task 1).
- Produces: tuplas de campo con 7º elemento opcional `required: bool` (ausente = `False`); `missing_required(profile_name: str, values: dict[str, str]) -> list[str]` (interna) devuelve los labels (sin `*`) de los campos `required` vacíos o ausentes; `validate_profile_tagset(profile_name: str, tags: dict[str, str]) -> list[str]` es la única entrada de validación para las vistas: concatena los errores de `validate_tagset` y, si faltan obligatorios, un mensaje `Missing required fields: A, B`.

- [ ] **Step 1: Escribir el test fallido.** Monkeypatchear `TAG_PROFILES` con un perfil de prueba `"T"` de dos campos (`("A", "a", FieldType.TEXT, False, None, None, True)` y `("B", "b", FieldType.TEXT, False, None, None)`). El `provider` automático se pasa relleno:

```python
def test_missing_required(monkeypatch):
    monkeypatch.setitem(TAG_PROFILES, "T", [A_REQUIRED, B_OPTIONAL])
    assert missing_required("T", {"provider": "T", "a": "", "b": ""}) == ["A"]
    assert missing_required("T", {"provider": "T", "b": "x"}) == ["A"]     # ausente
    assert missing_required("T", {"provider": "T", "a": "x", "b": ""}) == []

def test_validate_profile_tagset_combines_all_errors(monkeypatch):
    monkeypatch.setitem(TAG_PROFILES, "T", [A_REQUIRED, B_OPTIONAL])
    errs = validate_profile_tagset("T", {"provider": "T", "a": "", "b": "x" * 257})
    assert any("Missing required fields" in e and "A" in e for e in errs)
    assert any("b" in e for e in errs)                                  # longitud
    assert validate_profile_tagset("T", {"provider": "T", "a": "x", "b": ""}) == []
```

- [ ] **Step 2: Ejecutar el test y comprobar que falla** (`ImportError`).

- [ ] **Step 3: Implementar `missing_required` y `validate_profile_tagset`** en `meta_fields.py`; `missing_required` itera `profile_fields(profile_name)`; en `build_meta_fields` leer `required = item[6] if len(item) > 6 else False` y usar un `shown_label` con ` *` añadido cuando sea `True` en los cinco sitios que pintan el label (uniselect, multiselect, multifreetext, date y `styled_field(label)` del TEXT).

- [ ] **Step 4: Ejecutar el test y comprobar que pasa.**

- [ ] **Step 5: Enforcement con una sola llamada.** En `copy.py` `do_copy`, sustituir `validate_tagset(metadatos)` por `validate_profile_tagset(active_copy_profile["name"], metadatos)` y mantener el bloque `show_dialog` y `return` existentes (un solo diálogo con todos los errores). En `tag_manager.py`, lo mismo en `do_apply` con `active_profile["name"]`. En `_on_save_file_tags`, usar `validate_profile_tagset` cuando `file_editor_mode["mode"] == "profile"` y `validate_tagset` en el editor manual de key/value (no es de perfil). Importar `validate_profile_tagset` en ambos ficheros y quitar `validate_tagset` de `copy.py`.

- [ ] **Step 6: Verificación manual:** en IRB Standard e Histopathology IRB Core Facility, solo Provider lleva `*` (ya está relleno) y Copy no se bloquea.

- [ ] **Step 7: Commit**

```bash
git add bifrost-transfer/src bifrost-transfer/tests
git commit -m "feat(tags): añade el flag required y validate_profile_tagset como única validación de Copy/Aplicar"
```

---

### Task 4: Perfil Genomics

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (`TAG_PROFILES`)
- Test: `bifrost-transfer/tests/test_meta_fields.py`

**Interfaces:**
- Consumes: `check_tag_value` (Task 1), `profile_fields` y `detect_profile` (Task 2), tuplas con `required` (Task 3).
- Produces: `TAG_PROFILES["Advanced Genomic Technologies IRB Core Facility"]` con las keys `owner, users, date, application, library_kit, species, sample_type, comments` (el `provider` lo añade `profile_fields`). Constante de test: `GENO = "Advanced Genomic Technologies IRB Core Facility"`.

- [ ] **Step 1: Escribir los tests fallidos:**

```python
def test_genomics_profile_shape():
    keys = [f[1] for f in profile_fields(GENO)]
    assert keys == ["provider", "owner", "users", "date", "application",
                    "library_kit", "species", "sample_type", "comments"]
    required = {f[1] for f in profile_fields(GENO) if len(f) > 6 and f[6]}
    assert required == set(keys) - {"comments"}

def test_genomics_options_are_valid_s3_values():
    for f in profile_fields(GENO):
        for opt in (f[4] or []):
            value = opt[0] if isinstance(opt, tuple) else opt
            assert check_tag_value(value) is None, (f[1], value)

def test_application_all_joined_exceeds_limit():
    app = next(f for f in profile_fields(GENO) if f[1] == "application")[4]
    assert len(app) == 26
    assert check_tag_value(":".join(sorted(app))) is not None

def test_detect_genomics_by_provider():
    assert detect_profile({**COMMON, "provider": GENO}) == GENO
    assert detect_profile({"provider": GENO, "custom_tag": "x"}) == GENO
```

- [ ] **Step 2: Ejecutar los tests y comprobar que fallan** (`KeyError` del perfil).

- [ ] **Step 3: Añadir el perfil** a `TAG_PROFILES` con las tuplas del spec (todas `required=True` salvo `comments`; `allow_custom=False` en todos los selects; `comments` es TEXT con helper `"Incidents, QC deviations, notes"`; `date` DATE; `users` MULTIFREETEXT). Opciones de Application y Library Kit exactamente como en el spec, ya saneadas. Para no duplicar con Histopathology, extraer a constantes de módulo `_OWNER_OPTIONS` (la lista `(acr, f"{name} ({acr})")` ordenada por nombre) y `_USERS_HELPER` (el texto de ayuda de `users`) y usarlas en ambos perfiles.

- [ ] **Step 4: Ejecutar toda la suite y comprobar que pasa.**

- [ ] **Step 5: Verificación manual:** el perfil aparece en los selectores de Copy y Tag Manager con `*` en los obligatorios y Provider bloqueado. Con campos vacíos, Copy muestra "Missing required fields" con los labels.

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/meta_fields.py bifrost-transfer/tests
git commit -m "feat(tags): añade el perfil Advanced Genomic Technologies IRB Core Facility"
```

---

### Task 5: Documentación y log

**Files:**
- Modify: `README.md`, `docs/user/transfer-data.md`, `docs/user/tag-manager.md`, `docs/agent/frontend.md`, `docs/development/frontend.md` y lo que proponga `docs-update`; `docs/wiki/log.md`

- [ ] **Step 1: Ejecutar el skill `docs-update`** y aplicar solo los cambios que el usuario confirme. Debe cubrir: el nuevo nombre de Histopathology y el perfil de Genomics en `README.md` (l.93), `docs/user/transfer-data.md` (l.40 y l.72), `docs/user/tag-manager.md` (l.23), `docs/agent/frontend.md` (l.95) y `docs/development/frontend.md` (l.131); el 7º elemento `required`; `profile_fields`, `apply_provider` y `provider` automático y forzado; `check_tag_value`/`validate_tagset`/`validate_profile_tagset` y los límites 128/256; y `detect_profile` por `provider` con fallback por keys.

- [ ] **Step 2: Añadir una entrada en `docs/wiki/log.md`** con las decisiones: nombre del perfil = valor de `provider` (también en IRB Standard), `provider` automático y bloqueado, valores saneados (sin `'` ni paréntesis), flag `required`, validación unificada con límites 128/256 y fallback por keys para datos antiguos.

- [ ] **Step 3: Commit**

```bash
git add README.md docs
git commit -m "docs(tags): documenta el perfil Genomics, provider como nombre de perfil y la validación unificada"
```

---

## Self-Review

- **Cobertura del spec:** §1 perfil → Tasks 3 y 4; §2 obligatorios → Task 3; §3 validación unificada → Tasks 1 (`check_tag_value`, sin regex inline, `max_length` con constantes) y 3 (`validate_profile_tagset`, única llamada de las vistas); §4 provider = nombre del perfil, `profile_fields`, `apply_provider`, `detect_profile`, anchos y renombrado → Task 2; §5 documentación → Task 5; Notas (separador `:`, 10 tags, nombres como tags) → Global Constraints y tests de Task 2.
- **Consistencia de tipos:** `check_tag_value(text, max_len)`, `TAG_KEY_MAX`, `TAG_VALUE_MAX`, `profile_fields(profile_name)`, `apply_provider(profile_name, values)`, `missing_required(profile_name, values)`, `validate_profile_tagset(profile_name, tags)` y `detect_profile(tags)` se nombran igual en todas las tareas.
- **Orden:** Task 2 antes que 3 y 4 porque `validate_profile_tagset` y el perfil Genomics usan `profile_fields`; Task 3 antes que 4 porque Genomics usa el 7º elemento; Task 1 antes que 2, 3 y 4 porque llaman a `check_tag_value`.
- **Sin duplicación:** el regex vive solo en `check_tag_value`; las vistas validan solo con `validate_profile_tagset` (excepto el editor manual, que usa `validate_tagset`); la longitud total no se comprueba inline.
