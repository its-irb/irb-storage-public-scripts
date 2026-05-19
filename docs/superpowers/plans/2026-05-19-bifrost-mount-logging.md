# bifrost-mount logging improvements — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir timestamp completo a cada línea del log y capturar todas las acciones relevantes del usuario (login, selección de perfil/bucket, mount, unmount, errores) en el archivo de log de sesión de bifrost-mount.

**Architecture:** Un helper global `_log_event()` llama a `_write_to_log_file()`, que se modifica para prefijar `[YYYY-MM-DD HH:MM:SS]` a cada línea. Se insertan llamadas a `_log_event()` en los puntos clave del flujo de usuario. No hay cambios en la UI ni en el backend.

**Tech Stack:** Python, `bifrost-mount/src/main.py` — único archivo modificado.

---

## Archivos modificados

- `bifrost-mount/src/main.py` — todos los cambios están aquí

---

### Task 1: Timestamp en `_write_to_log_file` + helper `_log_event` + import de `__version__`

**Files:**
- Modify: `bifrost-mount/src/main.py:49-51` (imports — añadir `from version import __version__`)
- Modify: `bifrost-mount/src/main.py:86-93` (`_write_to_log_file` — añadir timestamp)
- Modify: `bifrost-mount/src/main.py:93` (añadir `_log_event` justo después)

- [ ] **Step 1: Añadir import de `__version__`**

En `bifrost-mount/src/main.py`, justo después de la línea `from config import APP_INFO` (línea ~51), añadir:

```python
from version import __version__
```

- [ ] **Step 2: Modificar `_write_to_log_file` para añadir timestamp**

Reemplazar el bloque actual (líneas 86-93):

```python
def _write_to_log_file(msg: str) -> None:
    """Escribe msg en el fichero de log de sesión. Falla silenciosamente."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg if msg.endswith("\n") else msg + "\n")
    except Exception:
        pass
```

Por:

```python
def _write_to_log_file(msg: str) -> None:
    """Escribe msg en el fichero de log de sesión con timestamp. Falla silenciosamente."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            line = msg if msg.endswith("\n") else msg + "\n"
            f.write(f"[{timestamp}] {line}")
    except Exception:
        pass


def _log_event(msg: str) -> None:
    """Registra un evento de usuario en el log de sesión."""
    _write_to_log_file(msg)
```

- [ ] **Step 3: Verificar manualmente**

Abrir una terminal en `bifrost-mount/` y ejecutar:

```bash
flet run
```

Comprobar que se crea un archivo en `~/bifrost-mount-logs/` y que las líneas del log de credenciales (si se renueva) tienen formato `[2026-05-19 14:23:01] ...`.

- [ ] **Step 4: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "feat(logging): add timestamp to log file entries + _log_event helper"
```

---

### Task 2: Log de inicio de app y flujo de login/perfil MinIO

**Files:**
- Modify: `bifrost-mount/src/main.py:1414` (`main()` — log de inicio)
- Modify: `bifrost-mount/src/main.py:178-195` (`do_login` → `_auth` — log attempt/success/fail)
- Modify: `bifrost-mount/src/main.py:1500-1503` (`on_minio_selected` — log de perfil)

- [ ] **Step 1: Log APP start en `main()`**

En la función `main(page: ft.Page)` (línea ~1414), añadir como primera línea del cuerpo:

```python
def main(page: ft.Page):
    _log_event(f"APP start — bifrost-mount v{__version__}")
    page.title             = "BIFROST MOUNT — IRB MinIO"
    # ... resto sin cambios
```

- [ ] **Step 2: Log de login en `_auth()`**

En `_build_login_content`, la función interna `_auth()` (línea ~178) actualmente hace:

```python
def _auth():
    creds = {"usuario": user, "password": pwd}
    ok, motivo = backend.validar_credenciales_ldap(creds)
    if ok:
        backend.ui_call(page, lambda: on_success(creds))
    else:
        msg = (
            "⚠️ Cannot reach the IRB network. Are you connected to the VPN?"
            if motivo == "vpn"
            else "Invalid credentials. Please try again."
        )
        def _fail():
            error_text.value   = msg
            error_text.visible = True
            login_btn.disabled = False
            loading.visible    = False
            page.update()
        backend.ui_call(page, _fail)
```

Reemplazarla por:

```python
def _auth():
    creds = {"usuario": user, "password": pwd}
    _log_event(f"LOGIN attempt — user: {user}")
    ok, motivo = backend.validar_credenciales_ldap(creds)
    if ok:
        _log_event(f"LOGIN success — user: {user}")
        backend.ui_call(page, lambda: on_success(creds))
    else:
        msg = (
            "⚠️ Cannot reach the IRB network. Are you connected to the VPN?"
            if motivo == "vpn"
            else "Invalid credentials. Please try again."
        )
        _log_event(f"LOGIN failed — user: {user} — {msg}")
        def _fail():
            error_text.value   = msg
            error_text.visible = True
            login_btn.disabled = False
            loading.visible    = False
            page.update()
        backend.ui_call(page, _fail)
```

- [ ] **Step 3: Log de perfil MinIO seleccionado**

En `on_minio_selected` (línea ~1500), añadir log tras asignar el estado:

```python
def on_minio_selected(eleccion: dict):
    state["servidor_minio"] = eleccion["servidor"]
    state["perfil_rclone"]  = eleccion["perfil"]
    state["endpoint"]       = eleccion["endpoint"]
    _log_event(f"PROFILE selected — {eleccion['perfil']} ({eleccion['endpoint']})")
    _go_credentials_or_mount()
```

- [ ] **Step 4: Verificar manualmente**

```bash
flet run
```

Hacer login. Abrir el archivo de log más reciente en `~/bifrost-mount-logs/` y verificar que aparecen:
```
[YYYY-MM-DD HH:MM:SS] APP start — bifrost-mount v...
[YYYY-MM-DD HH:MM:SS] LOGIN attempt — user: <tu_usuario>
[YYYY-MM-DD HH:MM:SS] LOGIN success — user: <tu_usuario>
[YYYY-MM-DD HH:MM:SS] PROFILE selected — <perfil> (<endpoint>)
```

- [ ] **Step 5: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "feat(logging): log app start, login attempts and MinIO profile selection"
```

---

### Task 3: Log de selección de bucket, mount y unmount

**Files:**
- Modify: `bifrost-mount/src/main.py:560-563` (`_select_bucket` en `build_rclone_browser`)
- Modify: `bifrost-mount/src/main.py:573-590` (`_unmount_bucket`)
- Modify: `bifrost-mount/src/main.py:593-620` (`_unmount_all`)
- Modify: `bifrost-mount/src/main.py:1237-1308` (`do_mount` → `_do`)

- [ ] **Step 1: Log de bucket seleccionado**

En `build_rclone_browser`, la función `_select_bucket` (línea ~560):

```python
def _select_bucket(bucket_name: str):
    selected_state["bucket"] = bucket_name
    _log_event(f"BUCKET selected — {bucket_name}")
    on_select(bucket_name)
    _render_buckets(selected_state.get("_all_buckets", []))
```

- [ ] **Step 2: Log de mount en `do_mount` → `_do`**

Dentro de `_build_mount_bucket`, la función interna `_do()` (línea ~1237). Añadir logs en inicio, éxito y cada rama de error. El bloque actual es:

```python
def _do():
    try:
        backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
        mp = backend.resolver_mount_point_destino(perfil_rclone, ruta)
        # ... espera y apertura de explorador ...
        mounted_state[ruta] = mp
        # ... _ok() callback ...
    except backend.WinFspMissingError:
        # ...
    except EnvironmentError as ex:
        # ...
    except Exception as ex:
        # ...
```

Reemplazarlo por:

```python
def _do():
    _log_event(f"MOUNT start — bucket: {ruta}, profile: {perfil_rclone}")
    try:
        backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
        mp = backend.resolver_mount_point_destino(perfil_rclone, ruta)

        # Esperar a que el mount esté listo (máx 10s)
        import time, platform as _platform
        sistema = _platform.system()
        for _ in range(50):
            time.sleep(0.2)
            try:
                os.listdir(mp)
                break
            except OSError:
                pass

        mounted_state[ruta] = mp
        _log_event(f"MOUNT success — bucket: {ruta}, path: {mp}")

        # Abrir explorador
        try:
            import time, platform as _platform
            sistema = _platform.system()
            if sistema == "Windows":
                os.startfile(mp)
            else:
                subprocess.Popen({"Darwin": ["open"], "Linux": ["xdg-open"]}[sistema] + [mp])
        except Exception as ex:
            print(f"[mount] Could not open explorer: {ex}")

        def _ok():
            mount_btn.disabled   = False
            mount_status.value   = "✅ Mounted!"
            mount_status.color   = C_ACCENT
            def _clear_status():
                import time; time.sleep(3)
                def _hide():
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                backend.ui_call(page, _hide)
            threading.Thread(target=_clear_status, daemon=True).start()
            threading.Timer(0.2, dest_browser_refresh).start()
            page.update()
        backend.ui_call(page, _ok)
    except backend.WinFspMissingError:
        _log_event(f"MOUNT error (WinFsp missing) — bucket: {ruta}")
        def _ask():
            mount_btn.disabled   = False
            mount_status.value   = ""
            mount_status.visible = False
            page.update()
            _prompt_install_winfsp(on_success=lambda: do_mount(e, ruta))
        backend.ui_call(page, _ask)
    except EnvironmentError as ex:
        err_str = str(ex)
        _log_event(f"MOUNT error (FUSE/WinFSP) — bucket: {ruta} — {err_str}")
        def _err():
            mount_btn.disabled   = False
            mount_status.value   = ""
            mount_status.visible = False
            page.update()
            show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
        backend.ui_call(page, _err)
    except Exception as ex:
        err_str = str(ex)
        _log_event(f"MOUNT error — bucket: {ruta} — {err_str}")
        def _err():
            mount_btn.disabled   = False
            mount_status.value   = ""
            mount_status.visible = False
            page.update()
            show_dialog(page, "Mount error", err_str, C_ERROR)
        backend.ui_call(page, _err)
```

- [ ] **Step 3: Log de unmount individual en `_unmount_bucket`**

En `build_rclone_browser`, función `_unmount_bucket` (línea ~573):

```python
def _unmount_bucket(bucket_name: str):
    mp = mounted_state.get(bucket_name)
    if not mp:
        return
    def _do():
        _log_event(f"UNMOUNT — bucket: {bucket_name}, path: {mp}")
        try:
            backend.desmontar_punto_montaje(mp)
        except Exception as ex:
            _log_event(f"UNMOUNT error — bucket: {bucket_name} — {ex}")
            print(f"[unmount] Error: {ex}")
        finally:
            mounted_state.pop(bucket_name, None)
        def _refresh():
            if selected_state["bucket"] == bucket_name:
                selected_state["bucket"] = None
                on_select("")
            _render_buckets(selected_state.get("_all_buckets", []))
        backend.ui_call(page, _refresh)
    threading.Thread(target=_do, daemon=True).start()
```

- [ ] **Step 4: Log de unmount all en `_unmount_all`**

En `build_rclone_browser`, función `_unmount_all` (línea ~593):

```python
def _unmount_all():
    def _do():
        _log_event(f"UNMOUNT ALL — {len(mounted_state)} mounts")
        for bname, mp in list(mounted_state.items()):
            try:
                backend.desmontar_punto_montaje(mp)
            except OSError as ex:
                print(f"[unmount_all] OSError {bname}: {ex} — trying taskkill fallback")
                if sys.platform == "win32":
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/IM", "rclone.exe"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    except Exception:
                        pass
            except Exception as ex:
                print(f"[unmount_all] Error {bname}: {ex}")
            finally:
                mounted_state.pop(bname, None)
        def _refresh():
            selected_state["bucket"] = None
            on_select("")
            _render_buckets(selected_state.get("_all_buckets", []))
        backend.ui_call(page, _refresh)
    threading.Thread(target=_do, daemon=True).start()
```

- [ ] **Step 5: Verificar manualmente**

```bash
flet run
```

1. Seleccionar un bucket — verificar `BUCKET selected` en el log
2. Montar el bucket — verificar `MOUNT start` y `MOUNT success`
3. Desmontar — verificar `UNMOUNT`

- [ ] **Step 6: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "feat(logging): log bucket selection, mount and unmount events"
```

---

### Task 4: Log de instalación de WinFsp

**Files:**
- Modify: `bifrost-mount/src/main.py:1168-1195` (`_worker` dentro de `_prompt_install_winfsp`)

- [ ] **Step 1: Añadir logs en `_worker`**

Dentro de `_prompt_install_winfsp`, la función `_worker()` (línea ~1168):

```python
def _worker():
    try:
        ok = backend.install_winfsp_windows(page=page, on_progress=_on_progress)
    except Exception as ex:
        err = str(ex)
        _log_event(f"WINFSP install error — {err}")
        def _err():
            _close(progress_dlg)
            show_dialog(
                page,
                "Error installing WinFsp",
                f"{err}\n\nYou can install it manually from https://winfsp.dev",
                C_ERROR,
            )
        backend.ui_call(page, _err)
        return

    def _done():
        _close(progress_dlg)
        if ok:
            _log_event("WINFSP install success")
            on_success()
        else:
            _log_event("WINFSP install cancelled")
            show_dialog(
                page,
                "Installation cancelled",
                "The WinFsp installation was cancelled. You can retry the mount whenever you want.",
                C_ERROR,
            )
    backend.ui_call(page, _done)
```

- [ ] **Step 2: Verificar**

Este paso solo se puede verificar si WinFsp no está instalado (Windows). Si ya está instalado, revisar el código visualmente para confirmar que las llamadas a `_log_event` están en su lugar.

- [ ] **Step 3: Commit**

```bash
git add bifrost-mount/src/main.py
git commit -m "feat(logging): log WinFsp installation result"
```
