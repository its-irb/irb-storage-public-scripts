# Simplificar variables de modo (IS_WEB / IS_LINUX_CLUSTER) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unificar `IS_LINUX_CLUSTER` y `DEV_WEB` en una única variable `IS_WEB` en bifrost-transfer, y eliminar `IS_LINUX_CLUSTER` completamente de bifrost-mount.

**Architecture:** bifrost-transfer queda con una sola variable de modo: `IS_WEB`, activada por `--web` en argv, por importación de Flet (runtime web), o por `BIFROST_CLUSTER=1`. Todo el código que antes leía `IS_LINUX_CLUSTER` en transfer pasa a leer `IS_WEB`. bifrost-mount elimina la variable y todo el bloque CIFS asociado.

**Tech Stack:** Python, Flet, FastAPI (sección OOD de transfer)

**Spec:** `docs/superpowers/specs/2026-06-02-simplificar-variables-modo-design.md`

---

## Ficheros afectados

| Fichero | Acción |
|---|---|
| `bifrost-transfer/src/main.py` | Modificar: definición de variables (líneas 78-86), 5 usos de `IS_LINUX_CLUSTER`/`DEV_WEB` |
| `bifrost-mount/src/main.py` | Modificar: eliminar definición IS_LINUX_CLUSTER, bloque CIFS completo, referencias en cleanup/close |
| `CLAUDE.md` | Modificar: tabla de variables de entorno, sección de flags de desarrollo |
| `docs/wiki/decisiones/variables-modo-is-web.md` | Crear: página de decisión |
| `docs/wiki/index.md` | Modificar: añadir entrada |
| `docs/wiki/log.md` | Modificar: añadir entrada de tarea |

---

## Task 1: bifrost-transfer — simplificar definición de variables de modo

**Files:**
- Modify: `bifrost-transfer/src/main.py:78-86`

- [ ] **Paso 1: Reemplazar las tres variables por una sola `IS_WEB`**

Buscar y reemplazar el bloque completo (líneas 78-86):

```python
#Para desarrollo local: DEV_WEB = True
DEV_WEB = os.environ.get("BIFROST_DEV") == "1"
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or DEV_WEB

# En Linux cluster el flujo incluye CIFS; en el resto se omite
# Para desarrollo local: BIFROST_CLUSTER = "1"
IS_LINUX_CLUSTER = (sys.platform == "linux" and "_linux_cluster" in os.path.basename(
    sys.argv[0] if sys.argv else "" 
)) or os.environ.get("BIFROST_CLUSTER") == "1"
```

Por:

```python
# Modo web: producción (BIFROST_CLUSTER=1), Flet web runtime, o dev local (--web)
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- [ ] **Paso 2: Verificar que el fichero arranca sin errores de importación**

```powershell
cd bifrost-transfer
python -c "import sys; sys.argv=['main']; exec(open('src/main.py').read().split('ft.run')[0])"
```

Esperado: sin `NameError` ni `SyntaxError`.

---

## Task 2: bifrost-transfer — reemplazar IS_LINUX_CLUSTER por IS_WEB (5 ocurrencias)

**Files:**
- Modify: `bifrost-transfer/src/main.py` (líneas 3745, 3836-3845, 3893, 4102, 4152)

- [ ] **Paso 1: `_cleanup_on_exit` — línea ~3745**

Buscar:
```python
        if mounts and IS_LINUX_CLUSTER:
```
Reemplazar por:
```python
        if mounts and IS_WEB:
```

- [ ] **Paso 2: Eliminar el bloque `on_close` de desktop — líneas ~3836-3845**

El handler solo desmontaba CIFS, que ahora es exclusivo del modo web. En desktop no hay CIFS que desmontar.

Buscar y eliminar el bloque completo:
```python
    if not IS_WEB:
        def on_close(e):
            if IS_LINUX_CLUSTER and state["mounts_activos"]:
                usuario = (
                    (state["credenciales_smb"] or {}).get("usuario")
                    or getpass.getuser()
                )
                backend.safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()

        page.on_close = on_close
```

- [ ] **Paso 3: `on_login_success` — línea ~3893**

Buscar:
```python
        if IS_LINUX_CLUSTER:
            show_loading("Fetching LDAP groups...")
```
Reemplazar por:
```python
        if IS_WEB:
            show_loading("Fetching LDAP groups...")
```

- [ ] **Paso 4: `do_close` — línea ~4102**

Buscar:
```python
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
```
Reemplazar por:
```python
        if IS_WEB and state["mounts_activos"]:
```

- [ ] **Paso 5: Sección OOD — línea ~4152: reemplazar `DEV_WEB`**

La variable `DEV_WEB` se usaba para saltarse la validación del token en desarrollo local. Ahora en dev local se usa `flet run --web`, por lo que `--web` en argv equivale a dev mode.

Buscar:
```python
        if not DEV_WEB:
            token = websocket.cookies.get("bifrost_auth_token")
```
Reemplazar por:
```python
        if "--web" not in sys.argv:
            token = websocket.cookies.get("bifrost_auth_token")
```

- [ ] **Paso 6: Verificar que no quedan referencias a `IS_LINUX_CLUSTER` o `DEV_WEB`**

```powershell
Select-String -Path "bifrost-transfer/src/main.py" -Pattern "IS_LINUX_CLUSTER|DEV_WEB|BIFROST_DEV"
```

Esperado: sin resultados.

- [ ] **Paso 7: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "refactor(transfer): fusionar IS_LINUX_CLUSTER y DEV_WEB en IS_WEB"
```

---

## Task 3: bifrost-mount — eliminar IS_LINUX_CLUSTER y bloque CIFS

**Files:**
- Modify: `bifrost-mount/src/main.py`

- [ ] **Paso 1: Eliminar la definición de IS_LINUX_CLUSTER (líneas ~58-62)**

Buscar y eliminar:
```python
# En Linux cluster el flujo incluye CIFS; en el resto se omite
# Para desarrollo local: BIFROST_LINUX = "1"
IS_LINUX_CLUSTER = (sys.platform == "linux" and "_linux_cluster" in os.path.basename(
    sys.argv[0] if sys.argv else ""
)) or os.environ.get("BIFROST_LINUX") == "1"
```

- [ ] **Paso 2: Eliminar el bloque CIFS completo de `_build_mount_bucket` (líneas ~913-1133)**

Buscar y eliminar desde el comentario hasta el cierre de `cifs_section`:
```python
    # ── Sección CIFS (solo Linux) ─────────────────────────────────────────
    if IS_LINUX_CLUSTER:
        cifs_shares_col   = ft.Column(spacing=6, tight=True)
        ...
        cifs_section = ft.Column(
            ...
        )
```

El bloque termina en la línea que cierra el `ft.Column` de `cifs_section` (línea ~1133: el `ft.Container(height=16)` y el cierre de `ft.Column`). El siguiente comentario que debe quedar es:
```python
    # ── Destino: selector de buckets ──────────────────────────────────────
```

- [ ] **Paso 3: Eliminar la referencia a `cifs_section` en el layout (línea ~1367)**

En el `ft.Column` del layout principal, buscar y eliminar la línea:
```python
                        *([cifs_section] if IS_LINUX_CLUSTER else []),
```

- [ ] **Paso 4: Simplificar `_cleanup_on_exit` (líneas ~1468-1473)**

Buscar:
```python
    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario") or getpass.getuser()
            try:
                backend.desmontar_todos_los_shares(usuario)
            except Exception as e:
                print(f"[atexit] Error unmounting shares: {e}")
```
Reemplazar por:
```python
    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()
```

- [ ] **Paso 5: Simplificar `do_close` (líneas ~1595-1599)**

Buscar:
```python
    def do_close():
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario") or getpass.getuser()
            backend.safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()
        page.window.close()
```
Reemplazar por:
```python
    def do_close():
        page.window.close()
```

- [ ] **Paso 6: Actualizar el docstring del módulo (líneas ~23-25)**

Buscar y eliminar las líneas del docstring que mencionan `IS_LINUX_CLUSTER`:
```
En Linux cluster (IS_LINUX_CLUSTER=True):
  - La vista de montado incluye una sección CIFS con checkboxes para montar shares
  - Botón opcional para usar credenciales de admin (admin_<usuario>)
```

- [ ] **Paso 7: Verificar que no quedan referencias a IS_LINUX_CLUSTER o BIFROST_LINUX**

```powershell
Select-String -Path "bifrost-mount/src/main.py" -Pattern "IS_LINUX_CLUSTER|BIFROST_LINUX"
```

Esperado: sin resultados.

- [ ] **Paso 8: Verificar arranque en modo desktop**

```bash
cd bifrost-mount
flet run
```

Esperado: la app arranca sin errores. La vista de montado no muestra ninguna sección CIFS.

- [ ] **Paso 9: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "refactor(mount): eliminar IS_LINUX_CLUSTER y bloque CIFS (se mueve a transfer web)"
```

---

## Task 4: Actualizar CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Paso 1: Actualizar la tabla de variables de entorno**

En la sección `## Variables de entorno`, la tabla actual tiene tres filas. Hacer estos cambios:

Eliminar la fila de `BIFROST_DEV`:
```
| `BIFROST_DEV=1` | transfer | Activa `IS_WEB`/`DEV_WEB` para simular modo web en local |
```

Actualizar la fila de `BIFROST_CLUSTER`:

De:
```
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_LINUX_CLUSTER` (incluye flujo CIFS/shares) |
```
A:
```
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal de producción OOD) |
```

Eliminar la fila de `BIFROST_LINUX`:
```
| `BIFROST_LINUX=1` | mount | Activa flujo de Linux cluster en `bifrost-mount` |
```

- [ ] **Paso 2: Actualizar la sección de flags de desarrollo**

En `## Cómo ejecutar`, el bloque de flags útiles:

De:
```bash
flet run --customuser     # Login con usuario distinto al del sistema
flet run --update         # Forzar autoupdate
python src/main.py --web  # (solo transfer) modo web
BIFROST_DEV=1 flet run    # (solo transfer) simular modo web en local
BIFROST_CLUSTER=1 BIFROST_DEV=1 flet run  # forzar flujo CIFS de cluster
BIFROST_LINUX=1 python src/main.py        # (mount) simular Linux cluster
```

A:
```bash
flet run --customuser     # Login con usuario distinto al del sistema
flet run --update         # Forzar autoupdate
flet run --web            # (solo transfer) modo web para desarrollo local
BIFROST_CLUSTER=1 python src/main.py --web  # (solo transfer) simular producción OOD
```

- [ ] **Paso 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: actualizar CLAUDE.md tras simplificación de variables de modo"
```

---

## Task 5: Actualizar la wiki LLM

**Files:**
- Create: `docs/wiki/decisiones/variables-modo-is-web.md`
- Modify: `docs/wiki/index.md`
- Modify: `docs/wiki/log.md`

- [ ] **Paso 1: Crear la página de decisión**

Crear `docs/wiki/decisiones/variables-modo-is-web.md`:

```markdown
---
type: decision
tags: [bifrost-transfer, bifrost-mount, variables-entorno, modo-web]
fuentes: [docs/superpowers/specs/2026-06-02-simplificar-variables-modo-design.md]
actualizado: 2026-06-02
---

# Variables de modo: unificación en IS_WEB

## Resumen
Se eliminaron `IS_LINUX_CLUSTER` y `DEV_WEB` de bifrost-transfer, fusionándolas en `IS_WEB`. En bifrost-mount, `IS_LINUX_CLUSTER` se eliminó completamente junto con el bloque CIFS.

## Detalle

**Por qué se fusionaron `IS_WEB` e `IS_LINUX_CLUSTER` en transfer:**
Ambas variables eran semánticamente equivalentes: la app se despliega en producción en Linux cluster vía Open OnDemand, siempre en modo web. Tenerlas separadas obligaba a mantener dos condiciones sincronizadas que siempre tenían el mismo valor en producción.

**Por qué desaparece `BIFROST_DEV`:**
Se usaba para simular modo web en local sin el flag `--web` de Flet. Con `flet run --web` disponible, la variable adicional era redundante. El entorno de desarrollo se alínea así con lo que hace Flet de forma nativa.

**Por qué desaparece `IS_LINUX_CLUSTER` de bifrost-mount:**
El flujo CIFS de cluster se moverá a bifrost-transfer web (tarea futura). Por ahora se elimina de mount, que queda con un único modo: desktop estándar.

**Señal de producción:**
`BIFROST_CLUSTER=1` sigue siendo la env var que activa `IS_WEB=True` en producción (lanzada por el script de Open OnDemand).

**Variable resultante en bifrost-transfer:**
```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

**Variable de token en sección OOD:**
`if not DEV_WEB:` se reemplazó por `if "--web" not in sys.argv:` — la validación del token JWT se salta cuando Flet lanza en modo dev (`--web` en argv) y se aplica en producción (`BIFROST_CLUSTER=1`).

## Fuentes
- `docs/superpowers/specs/2026-06-02-simplificar-variables-modo-design.md` — spec completo con decisión y alcance
```

- [ ] **Paso 2: Añadir entrada en `index.md`**

En `docs/wiki/index.md`, bajo `## Decisiones`, añadir:
```markdown
- [Variables de modo: unificación en IS_WEB](decisiones/variables-modo-is-web.md) — por qué IS_LINUX_CLUSTER y DEV_WEB se fusionaron en IS_WEB y BIFROST_CLUSTER=1 es la señal de producción.
```

- [ ] **Paso 3: Añadir entrada en `log.md`**

Añadir al principio de `docs/wiki/log.md` (append en orden cronológico inverso, o al final si el fichero es cronológico ascendente — respetar el orden existente):

```markdown
## [2026-06-02] task | simplificar variables de modo IS_WEB / IS_LINUX_CLUSTER
Se fusionaron `IS_LINUX_CLUSTER` y `DEV_WEB` en una única variable `IS_WEB` en bifrost-transfer. En bifrost-mount se eliminó `IS_LINUX_CLUSTER` y todo el bloque CIFS (que se moverá a transfer web en una tarea futura). La env var `BIFROST_CLUSTER=1` pasa a ser la señal canónica de producción para modo web.
```

- [ ] **Paso 4: Commit**

```bash
git add docs/wiki/decisiones/variables-modo-is-web.md docs/wiki/index.md docs/wiki/log.md
git commit -m "wiki: decisión sobre unificación de variables de modo en IS_WEB"
```
