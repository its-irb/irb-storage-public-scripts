# WinFsp Auto-Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cuando `bifrost-mount` detecta que falta WinFsp en Windows, ofrecer descargar e instalar automáticamente la última release oficial de `winfsp/winfsp` en lugar de solo mostrar un link.

**Architecture:** Excepción dedicada `WinFspMissingError` levantada por el backend; nuevas funciones en `backend.py` para resolver la última URL del MSI vía GitHub API, descargarlo a `%TEMP%`, y lanzar `msiexec /qb`. UI en `bifrost-mount/src/main.py` con diálogo de confirmación, progreso y reintento automático del mount tras instalación correcta.

**Tech Stack:** Python 3, Flet (UI), `urllib.request` (descarga, ya en uso), `subprocess` (msiexec), GitHub Releases API.

**Spec:** `docs/superpowers/specs/2026-05-19-winfsp-auto-install-design.md`

**Nota sobre tests:** El repo no tiene suite automatizada (ver `CLAUDE.md` §Tests). La validación es manual ejecutando `flet run` en una máquina Windows. Por eso este plan **no incluye tests unitarios pytest**; cada tarea acaba con pasos de validación manual concretos.

---

## File Structure

- **Modificar** `shared/bifrost_backend/backend.py`:
  - Añadir excepción `WinFspMissingError`.
  - Añadir 3 funciones nuevas: `_winfsp_latest_msi_url`, `_download_winfsp_msi`, `install_winfsp_windows`.
  - Modificar `mount_rclone_S3_prefix_to_folder` (~línea 604) para levantar `WinFspMissingError` en vez de `EnvironmentError`.
- **Modificar** `bifrost-mount/src/main.py`:
  - Añadir helper local `_prompt_install_winfsp(page, on_success)`.
  - Sustituir el bloque `except EnvironmentError` del flujo `do_mount` (~línea 1193-1201) para distinguir `WinFspMissingError`.
- **Modificar** `CLAUDE.md` y `README.md` al final.
- **Añadir entrada** en `docs/wiki/log.md` al cerrar la tarea.

---

## Task 1: Añadir excepción `WinFspMissingError` en el backend

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (justo encima del bloque `_check_winfsp_windows`, ~línea 310)

- [ ] **Step 1: Localizar el bloque "DETECCIÓN DE FUSE / WINFSP"**

Buscar la cabecera de sección:
```
# ============================================================================
# DETECCIÓN DE FUSE / WINFSP
# ============================================================================
```
en `shared/bifrost_backend/backend.py`.

- [ ] **Step 2: Insertar la nueva clase de excepción justo después de la cabecera**

```python
class WinFspMissingError(EnvironmentError):
    """Falta WinFsp en Windows. Se distingue de EnvironmentError genérico
    para que la UI pueda ofrecer auto-instalación en lugar de solo mostrar
    un link a winfsp.dev."""
    pass
```

- [ ] **Step 3: Verificar import / sintaxis**

Run: `python -c "import ast; ast.parse(open(r'shared/bifrost_backend/backend.py', encoding='utf-8').read())"`
Expected: sin output (parseo OK).

- [ ] **Step 4: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): add WinFspMissingError exception"
```

---

## Task 2: Función `_winfsp_latest_msi_url()` — resolver URL de la última release

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (después de `_check_winfsp_windows`, antes de la siguiente sección)

- [ ] **Step 1: Añadir la función**

```python
def _winfsp_latest_msi_url() -> tuple[str, str]:
    """Devuelve (url_descarga_msi, tag_version) de la última release de WinFsp en GitHub.

    Levanta RuntimeError si la API no responde o no hay asset .msi.
    """
    api_url = "https://api.github.com/repos/winfsp/winfsp/releases/latest"
    try:
        resp = requests.get(api_url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as ex:
        raise RuntimeError(f"No se pudo consultar la API de GitHub de WinFsp: {ex}")

    tag = data.get("tag_name", "")
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name.lower().endswith(".msi") and url:
            return url, tag

    raise RuntimeError("No se encontró ningún asset .msi en la última release de WinFsp.")
```

- [ ] **Step 2: Verificar sintaxis**

Run: `python -c "import ast; ast.parse(open(r'shared/bifrost_backend/backend.py', encoding='utf-8').read())"`
Expected: sin output.

- [ ] **Step 3: Smoke-test manual de la API (no commitea nada)**

Run en la venv de `bifrost-mount`:
```powershell
python -c "import sys; sys.path.insert(0, 'shared'); sys.path.insert(0, 'bifrost-mount/src'); from bifrost_backend.backend import _winfsp_latest_msi_url; print(_winfsp_latest_msi_url())"
```
Expected: imprime una tupla `('https://github.com/winfsp/winfsp/releases/download/...msi', 'v2.x.x')`.

Si falla por VPN/red, anotar y continuar (no bloqueante para commit; la función se valida realmente en Task 6).

- [ ] **Step 4: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): resolve latest WinFsp MSI URL via GitHub API"
```

---

## Task 3: Función `_download_winfsp_msi()` — descargar el MSI a %TEMP%

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (justo después de `_winfsp_latest_msi_url`)

- [ ] **Step 1: Añadir la función**

```python
def _download_winfsp_msi(url: str, tag: str) -> Path:
    """Descarga el MSI de WinFsp a %TEMP%\\winfsp-<tag>.msi y devuelve el path.

    Levanta RuntimeError si la descarga falla o el fichero resultante está vacío.
    """
    safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", tag) or "latest"
    dest = Path(tempfile.gettempdir()) / f"winfsp-{safe_tag}.msi"
    try:
        with requests.get(url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        f.write(chunk)
    except Exception as ex:
        raise RuntimeError(f"No se pudo descargar WinFsp MSI: {ex}")

    if not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"El MSI descargado está vacío: {dest}")

    return dest
```

- [ ] **Step 2: Verificar sintaxis**

Run: `python -c "import ast; ast.parse(open(r'shared/bifrost_backend/backend.py', encoding='utf-8').read())"`
Expected: sin output.

- [ ] **Step 3: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): download WinFsp MSI to temp dir"
```

---

## Task 4: Función `install_winfsp_windows()` — orquestador completo

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (después de `_download_winfsp_msi`)

- [ ] **Step 1: Añadir la función**

```python
def install_winfsp_windows(page=None, on_progress=None) -> bool:
    """Descarga e instala WinFsp en Windows.

    Args:
        page: objeto Flet page (opcional, solo para tipado uniforme).
        on_progress: callable(str) opcional que recibe mensajes de estado
                     ("Descargando...", "Instalando...") para mostrarlos en UI.

    Returns:
        True si WinFsp queda instalado correctamente.
        False si el usuario canceló el UAC (no es un error real).

    Raises:
        RuntimeError si falla la consulta a GitHub, la descarga o la instalación.
    """
    if platform.system() != "Windows":
        raise RuntimeError("install_winfsp_windows solo es válido en Windows")

    def _emit(msg: str) -> None:
        if on_progress is not None:
            try:
                on_progress(msg)
            except Exception:
                pass

    _emit("Checking latest WinFsp version...")
    url, tag = _winfsp_latest_msi_url()

    _emit(f"Downloading WinFsp {tag}...")
    msi_path = _download_winfsp_msi(url, tag)

    _emit(f"Installing WinFsp {tag}...")
    try:
        result = subprocess.run(
            ["msiexec", "/i", str(msi_path), "/qb", "/norestart"],
            check=False,
        )
    except FileNotFoundError as ex:
        raise RuntimeError(f"No se encontró msiexec: {ex}")

    rc = result.returncode
    if rc in (0, 3010):
        # 0 = OK, 3010 = OK pero requiere reinicio (poco habitual con WinFsp).
        if _check_winfsp_windows():
            return True
        raise RuntimeError(
            f"msiexec terminó con código {rc} pero WinFsp sigue sin detectarse."
        )
    if rc == 1602:
        # Usuario canceló UAC o el wizard del MSI.
        return False
    raise RuntimeError(f"msiexec falló con código de salida {rc}.")
```

- [ ] **Step 2: Verificar sintaxis**

Run: `python -c "import ast; ast.parse(open(r'shared/bifrost_backend/backend.py', encoding='utf-8').read())"`
Expected: sin output.

- [ ] **Step 3: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): install_winfsp_windows orchestrator (download + msiexec)"
```

---

## Task 5: Cambiar el `raise` en `mount_rclone_S3_prefix_to_folder` para usar `WinFspMissingError`

**Files:**
- Modify: `shared/bifrost_backend/backend.py:603-605`

- [ ] **Step 1: Localizar el bloque actual**

Buscar:
```python
    elif sistema == "Windows":
        if not _check_winfsp_windows():
            raise EnvironmentError("WinFSP not detected. Download from: https://winfsp.dev")
```

- [ ] **Step 2: Sustituirlo por**

```python
    elif sistema == "Windows":
        if not _check_winfsp_windows():
            raise WinFspMissingError("WinFsp not detected on this system.")
```

- [ ] **Step 3: Verificar sintaxis**

Run: `python -c "import ast; ast.parse(open(r'shared/bifrost_backend/backend.py', encoding='utf-8').read())"`
Expected: sin output.

- [ ] **Step 4: Verificar que `WinFspMissingError` hereda de `EnvironmentError`**

Run: `python -c "import sys; sys.path.insert(0, 'shared'); sys.path.insert(0, 'bifrost-mount/src'); from bifrost_backend.backend import WinFspMissingError; assert issubclass(WinFspMissingError, EnvironmentError); print('OK')"`
Expected: `OK`. Esto garantiza que el `except EnvironmentError` actual sigue capturándola hasta que se modifique la UI en la siguiente tarea — no rompe nada de forma temporal.

- [ ] **Step 5: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): raise WinFspMissingError instead of generic EnvironmentError"
```

---

## Task 6: UI — diálogo de confirmación y flujo de instalación en `bifrost-mount`

**Files:**
- Modify: `bifrost-mount/src/main.py` (bloque `do_mount`, alrededor de las líneas 1193-1210)

- [ ] **Step 1: Añadir helper `_prompt_install_winfsp` dentro del scope de la vista del mount**

Localizar la función `do_mount` (~línea 1100) y, justo antes de su definición, añadir este helper en el mismo scope. El helper construye un diálogo Flet con dos botones; al pulsar "Instalar" lanza la descarga + msiexec en un hilo seguro y, si todo va bien, reintenta el mount automáticamente:

```python
def _prompt_install_winfsp(on_success):
    """Pregunta al usuario si quiere descargar e instalar WinFsp.
    Si acepta y la instalación termina OK, ejecuta on_success() (reintento del mount).
    """
    import flet as ft

    def _close(dlg):
        dlg.open = False
        page.update()

    def _show_info(title, body):
        show_dialog(page, title, body, C_ERROR)

    def _do_install(_e):
        _close(confirm_dlg)

        # Diálogo de progreso (modal, sin botones).
        progress_text = ft.Text("Starting...")
        progress_dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Installing WinFsp"),
            content=ft.Column(
                [ft.ProgressRing(), progress_text],
                tight=True,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        )
        page.overlay.append(progress_dlg)
        progress_dlg.open = True
        page.update()

        def _on_progress(msg):
            def _upd():
                progress_text.value = msg
                page.update()
            backend.ui_call(page, _upd)

        def _worker():
            try:
                ok = backend.install_winfsp_windows(page=page, on_progress=_on_progress)
            except Exception as ex:
                err = str(ex)
                def _err():
                    _close(progress_dlg)
                    _show_info(
                        "Error installing WinFsp",
                        f"{err}\n\nYou can install it manually from https://winfsp.dev",
                    )
                backend.ui_call(page, _err)
                return

            def _done():
                _close(progress_dlg)
                if ok:
                    on_success()
                else:
                    _show_info(
                        "Installation cancelled",
                        "The WinFsp installation was cancelled. You can retry "
                        "the mount operation whenever you want.",
                    )
            backend.ui_call(page, _done)

        backend.safe_thread(page, _worker).start()

    def _do_cancel(_e):
        _close(confirm_dlg)
        _show_info(
            "WinFsp not detected",
            "WinFsp is required to mount S3 folders. Download it from "
            "https://winfsp.dev",
        )

    confirm_dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text("WinFsp is not installed"),
        content=ft.Text(
            "WinFsp is required to mount S3 folders on Windows.\n\n"
            "Do you want to download and install the latest version now? "
            "Administrator permissions will be required."
        ),
        actions=[
            ft.TextButton("Install", on_click=_do_install),
            ft.TextButton("Cancel", on_click=_do_cancel),
        ],
    )
    page.overlay.append(confirm_dlg)
    confirm_dlg.open = True
    page.update()
```

- [ ] **Step 2: Modificar el bloque `except EnvironmentError` en `do_mount`**

Localizar:
```python
            except EnvironmentError as ex:
                err_str = str(ex)
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
                backend.ui_call(page, _err)
```

Y sustituirlo por:
```python
            except backend.WinFspMissingError:
                def _ask():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    _prompt_install_winfsp(on_success=lambda: do_mount(e))
                backend.ui_call(page, _ask)
            except EnvironmentError as ex:
                err_str = str(ex)
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
                backend.ui_call(page, _err)
```

Nota: el `on_success=lambda: do_mount(e)` reintenta el mount con el mismo evento que disparó el original. Si la firma de `do_mount` espera un evento Flet y `e` no está en scope en el punto exacto, usar `lambda: do_mount(None)` (verificar en el código real al editar).

- [ ] **Step 3: Verificar sintaxis del fichero**

Run: `python -c "import ast; ast.parse(open(r'bifrost-mount/src/main.py', encoding='utf-8').read())"`
Expected: sin output.

- [ ] **Step 4: Validación manual en Windows**

Requisitos: máquina Windows sin WinFsp instalado (o desinstalarlo previamente desde "Aplicaciones instaladas"). VPN Nexica activa.

```powershell
cd bifrost-mount
.\.venv\Scripts\Activate.ps1
flet run
```

Acciones:
1. Login normal, llegar a la vista de mount.
2. Pulsar **Mount**.
3. Verificar: aparece el diálogo "WinFsp is not installed" con botones **Install / Cancel**.
4. Pulsar **Install**.
5. Verificar: aparece diálogo modal de progreso con mensajes "Checking latest WinFsp version..." → "Downloading WinFsp v2.x.x..." → "Installing WinFsp v2.x.x...".
6. Aprobar el UAC cuando aparezca el pop-up del sistema.
7. Verificar: tras "Installer complete" del MSI, el diálogo de progreso se cierra y el mount se reintenta automáticamente, terminando con "✅ Mounted!".

- [ ] **Step 5: Validación manual — cancelar el UAC**

Repetir el flujo del Step 4 pero, al aparecer el UAC, pulsar **No**.
Expected: diálogo "Installation cancelled" con mensaje informativo. Botón **Mount** vuelve a estar habilitado.

- [ ] **Step 6: Validación manual — cancelar antes de instalar**

Repetir desde el Step 4.3 pero pulsar **Cancel** en el primer diálogo.
Expected: aparece el mensaje informativo "WinFsp not detected" con el link a `https://winfsp.dev`.

- [ ] **Step 7: Validación manual — sin red**

Con WinFsp desinstalado y sin conexión (desconectar VPN/red), repetir Steps 4.1-4.4.
Expected: diálogo "Error installing WinFsp" con el mensaje de error de red y la URL de fallback.

- [ ] **Step 8: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "feat(mount): auto-install WinFsp on Windows when missing"
```

---

## Task 7: Actualizar documentación (`CLAUDE.md` y `README.md`)

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Releer ambos ficheros**

Run: `Read CLAUDE.md` y `Read README.md`.

- [ ] **Step 2: En `CLAUDE.md` — añadir gotcha sobre WinFsp**

En la sección "Convenciones y gotchas críticas", añadir un nuevo punto numerado al final:

```markdown
8. **Auto-instalación de WinFsp (solo `bifrost-mount`, Windows)**: si falta WinFsp al montar, el backend levanta `WinFspMissingError` (subclase de `EnvironmentError`). La UI ofrece descargar e instalar la última release oficial desde `github.com/winfsp/winfsp` vía `backend.install_winfsp_windows()`. Requiere UAC; el MSI se cachea en `%TEMP%`. `bifrost-transfer` no tiene este flujo.
```

- [ ] **Step 3: En `README.md` — actualizar la sección de requisitos en Windows**

Localizar la mención de WinFsp en el README (probablemente en una sección de requisitos / instalación) y añadir/ajustar una frase:

> En Windows, `bifrost-mount` detecta automáticamente si falta WinFsp y ofrece descargar e instalar la última versión oficial (requiere permisos de administrador). La instalación manual desde https://winfsp.dev sigue siendo opcional.

Si el README no menciona WinFsp explícitamente todavía, añadir esa nota en la sección que describa `bifrost-mount`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: document WinFsp auto-install behavior in bifrost-mount"
```

---

## Task 8: Entrada en el log de la wiki

**Files:**
- Modify: `docs/wiki/log.md`

- [ ] **Step 1: Leer `docs/wiki/CLAUDE_WIKI.md`** para confirmar el formato de las entradas del log.

- [ ] **Step 2: Añadir una entrada nueva al log** con fecha 2026-05-19 resumiendo:
  - qué se ha hecho (auto-install WinFsp en bifrost-mount),
  - decisiones clave (descarga bajo demanda, fuente GitHub Releases API, solo bifrost-mount),
  - referencia al spec y al plan,
  - cualquier gotcha encontrado durante validación manual.

- [ ] **Step 3: Si aplica según `CLAUDE_WIKI.md`, crear/actualizar página dedicada** (p. ej. `docs/wiki/windows-winfsp.md`) con el detalle del flujo.

- [ ] **Step 4: Commit**

```bash
git add docs/wiki
git commit -m "docs(wiki): log WinFsp auto-install feature"
```

---

## Validación final (sin commit propio)

- [ ] **Step 1: Smoke test cross-plataforma**

En macOS o Linux (cualquier máquina dev):
```bash
cd bifrost-mount
flet run
```
Expected: la app arranca y el flujo de mount funciona igual que antes (no se ha tocado el flujo no-Windows). El nuevo símbolo `WinFspMissingError` solo se importa, no rompe nada.

- [ ] **Step 2: Confirmar que `bifrost-transfer` sigue compilando**

```bash
cd bifrost-transfer
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read())"
```
Expected: sin output. `bifrost-transfer` no se ha modificado en este plan; este check confirma que ningún cambio compartido en `backend.py` lo rompe.

- [ ] **Step 3: Si la rama está lista para revisión, pasar a la skill `superpowers:finishing-a-development-branch`.**