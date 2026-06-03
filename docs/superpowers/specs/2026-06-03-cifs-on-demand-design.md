# CIFS Mount: On-Demand desde la Vista de Copia

**Fecha:** 2026-06-03  
**App:** bifrost-transfer  
**Archivo principal:** `bifrost-transfer/src/main.py`

---

## Problema

Actualmente en modo web (IS_WEB), el flujo de arranque siempre muestra la selección de shares CIFS antes de llegar a la vista de copia, aunque el usuario no quiera montar ningún share. Esto añade fricción innecesaria y bloquea la llegada a la vista principal.

## Objetivo

Mover la selección y montado de shares CIFS a un botón opcional en la vista de copia, accesible en cualquier momento pero no obligatorio.

---

## Cambios de flujo

### Flujo anterior (IS_WEB)
```
login → load_groups → _after_privileges → load_shares → _build_shares_content → go_minio → go_copy
```

### Flujo nuevo (IS_WEB y desktop, idénticos)
```
login → go_minio → go_copy
```

El bloque de carga lazy de LDAP groups / SMB credentials / shares se mueve a `go_cifs()`, invocado solo cuando el usuario pulsa el botón "Mount CIFS".

---

## Cambios en `main()` (función principal de la app)

### Eliminar de `on_login_success` (IS_WEB)
- Eliminar la llamada a `backend.get_ldap_groups` y todo el flujo `_after_privileges` / `_load_shares` que ocurre en el arranque.
- En IS_WEB, `on_login_success` simplemente llama `go_minio()`, igual que en desktop.

### Nueva función `go_cifs()`
```
go_cifs():
  1. Si state["credenciales_smb"] ya está cargado → ir directo a _build_shares_content
  2. Si no:
     a. show_loading("Loading accessible shares...")
     b. En hilo background:
        - backend.get_ldap_groups(usuario) → state["grupos_ldap"]
        - backend.construir_credenciales_smb(creds_ldap, usar_privilegios=False, admin=None)
          → state["credenciales_smb"]
        - backend.obtener_shares_accesibles(...) → state["shares_accesibles"]
        - backend.configurar_perfiles_smb_si_faltan(...) → state["perfiles_configurados"]
     c. show_screen(_build_shares_content(..., on_back=go_copy))
```

No se pregunta sobre privilegios admin al entrar. El botón admin es opcional dentro de la vista (ver sección `_build_shares_content`).

### Cambio en `go_copy()`
- Añadir `on_cifs=go_cifs` en la llamada a `_build_copy_content`.

### Cierre / atexit
Sin cambios. `_cleanup_on_exit` y `do_close` ya comprueban `state["mounts_activos"]` antes de desmontar. Si el usuario nunca usó CIFS, la lista está vacía y no pasa nada. Si lo usó, los shares se desmontan correctamente.

---

## Cambios en `_build_copy_content`

### Nuevo parámetro
```python
on_cifs: Callable | None = None
```

### Nuevo botón "Mount CIFS"
- Texto: `"⊞ Mount CIFS"`
- Estilo: `btn_secondary`
- Visible: solo si `IS_WEB and on_cifs is not None`
- Posición: barra superior, junto a `back_btn`, `tags_btn`, `expiry_badge`, `renew_btn`
- `on_click`: llama `on_cifs()`

---

## Cambios en `_build_shares_content`

### Parámetro nuevo
```python
on_back: Callable   # reemplaza on_continue
```
Se elimina `on_continue` como nombre semántico (antes era "ir a go_minio"). Ahora el callback devuelve a `go_copy`.

### UX de las filas de shares

**Antes:** checkboxes + botón bulk "Continue →"  
**Después:** filas `GestureDetector` con comportamiento:

| Acción | Resultado |
|---|---|
| Single-click | Selecciona/resalta la fila (highlight visual) |
| Double-click | Monta el share inmediatamente |

**Estado visual por fila:**
- Normal: icono carpeta + nombre del share
- Seleccionada: borde `C_PRIMARY`
- Montando: spinner inline + texto "Mounting..."
- Montada: badge verde "Mounted" (icono check + texto)
- Error: texto rojo con mensaje corto

Los shares ya presentes en `mounts_activos` al entrar a la vista muestran el badge "Mounted" directamente.

### Montado on double-click
```python
def _mount_share(share_name):
    # Mostrar spinner en la fila
    # backend.montar_shares_seleccionados([share_name], recursos_cifs_dict, mounts_activos)
    # Si ok → badge "Mounted"
    # Si error → texto rojo en la fila
```
El montado ocurre en `backend.safe_thread` para no bloquear la UI.

### Botones de la vista
- **"← Back"** (btn_secondary): llama `on_back()` (→ `go_copy`). No bloquea aunque haya shares montándose.
- **"Update SMB credentials"**: se mantiene igual.
- **"Admin credentials"** (btn_secondary): visible **solo si `"its" in state["grupos_ldap"]`**. Al pulsarlo abre un diálogo que pide la contraseña del usuario `admin_<usuario>`. Si las credenciales son correctas:
  - `state["usar_privilegios"] = True`
  - `state["credenciales_admin"] = {...}`
  - Reconstruye `state["credenciales_smb"]` con privilegios elevados
  - Recarga `state["shares_accesibles"]` (show_loading inline o spinner en botón)
  - Refresca la lista de shares en la vista
  - El botón pasa a estado "Admin active" (deshabilitado o badge verde) para indicar que ya está activo
- Se elimina **"Continue →"**.

---

## Archivos modificados

| Archivo | Cambios |
|---|---|
| `bifrost-transfer/src/main.py` | `on_login_success`, nueva `go_cifs()`, `go_copy()`, `_build_copy_content`, `_build_shares_content` |

No se toca `shared/` ni ningún otro fichero.

---

## Notas de implementación

- `_ask_admin_creds` y `_after_privileges` se eliminan del flujo de arranque. La lógica de admin credentials vive ahora dentro de `_build_shares_content` como callback del botón "Admin credentials".
- El bloque de eliminación de shares del arranque afecta solo a IS_WEB; desktop nunca tuvo ese flujo.
- La variable `state["credenciales_smb"]` actúa como caché: si el usuario pulsa "Mount CIFS" dos veces, la segunda no recarga grupos LDAP. La caché se invalida si el usuario activa credenciales admin (se reconstruye con privilegios elevados).
- `_build_shares_content` necesita recibir también `grupos_ldap` (para saber si mostrar el botón admin) y un callback para recargar shares con nuevas credenciales.
