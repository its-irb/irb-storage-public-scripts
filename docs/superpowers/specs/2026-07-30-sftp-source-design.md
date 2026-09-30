# Diseño: Origen SFTP en bifrost-transfer

**Fecha:** 2026-07-30
**Rama:** feature/sftp
**Alcance:** bifrost-transfer (vista de copia, backend compartido)

---

## Resumen

Hoy el campo "Source path" de la vista de copia acepta una ruta local o un remote rclone ya existente (`profile:/path`), rellenado mediante los botones "📄 File" / "📁 Folder" (picker local en desktop, browser propio en web). No hay forma de traer datos directamente desde un servidor SFTP externo.

Este cambio añade un tercer origen: **"🌐 SFTP"**. El usuario introduce host/puerto/usuario/contraseña, la app crea un perfil rclone temporal, navega las carpetas remotas con el mismo browser que ya se usa para el destino S3, y al seleccionar una carpeta el campo origen queda relleno con `perfil:/path` — **exactamente el mismo formato que ya acepta hoy**, por lo que `do_copy`/`do_check` no requieren ningún cambio.

Autenticación: solo usuario/contraseña (no clave privada). Disponible en ambos modos (desktop y web).

---

## Usuarios objetivo

Cualquier usuario de `bifrost-transfer` en el flujo de copia (desktop o web) que necesite traer datos desde un servidor SFTP externo en vez de una carpeta de red o local.

---

## Decisión de seguridad: perfil rclone temporal, no connection-string

Se evaluaron dos opciones para las credenciales SFTP:

1. **Connection-string "on the fly" de rclone** (`:sftp,host=...,pass=<obscured>:`) — cero huella en disco, pero requiere adaptar `preparar_origen_para_check` y `traducir_a_ruta_local_montada`, que hoy parsean `origen` asumiendo que el nombre de perfil no contiene `:` ni `,`.
2. **Perfil temporal en `rclone.conf`** (mismo patrón que `crear_perfil_rclone_smb`) — consistente con el resto del código, sin tocar el parsing de `origen`, pero implica una ventana en la que la contraseña ofuscada vive en disco.

**Decisión: opción 2**, con limpieza agresiva para minimizar la ventana de exposición (ver sección de cleanup). La contraseña se guarda siempre ofuscada (`rclone obscure`), nunca en claro.

---

## Sección 1: Backend — `shared/bifrost_backend/backend.py`

Nuevo bloque de sección, mismo estilo que el resto del módulo:

```python
# ============================================================================
# GESTIÓN SFTP (ORIGEN EFÍMERO)
# ============================================================================

def crear_perfil_rclone_sftp(
    nombre_perfil: str,
    host: str,
    port: str,
    username: str,
    password: str,
) -> None:
    """Crea (o reemplaza) un perfil SFTP temporal en rclone.conf."""
    rclone = get_rclone_executable()
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
    config[nombre_perfil] = {
        "type": "sftp",
        "host": host,
        "port": port,
        "user": username,
        "pass": subprocess.check_output(
            [rclone, "obscure", password],
            text=True,
            **_subprocess_kwargs(),
        ).strip(),
    }
    with open(config_path, "w") as f:
        config.write(f)


def eliminar_perfil_rclone(nombre_perfil: str, rclone_config_path: str | None = None) -> None:
    """Borra una sección de rclone.conf si existe."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
        with open(config_path, "w") as f:
            config.write(f)


def limpiar_perfiles_rclone_con_prefijo(prefijo: str, rclone_config_path: str | None = None) -> None:
    """Borra todas las secciones cuyo nombre empiece por *prefijo* (barrido de huérfanos)."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    for nombre in [s for s in config.sections() if s.startswith(prefijo)]:
        eliminar_perfil_rclone(nombre, config_path)
```

`limpiar_perfiles_rclone_con_prefijo` reutiliza `eliminar_perfil_rclone` para el borrado individual — no duplica la lógica de abrir/escribir `rclone.conf`.

**Validación de conexión**: se reutiliza `rclone_lsd(nombre_perfil, "")` (ya existente) contra el perfil recién creado. Si lanza excepción, se traduce el mensaje según el contenido del stderr (ver Manejo de errores).

**Prefijo de nombre de perfil**: `sftp-src-{uuid4().hex[:8]}` — aleatorio para evitar colisiones entre conexiones sucesivas y para que el barrido de huérfanos (`limpiar_perfiles_rclone_con_prefijo("sftp-src-")`) los reconozca sin ambigüedad.

**Barrido de seguridad al login**: se llama a `limpiar_perfiles_rclone_con_prefijo("sftp-src-")` una vez, justo tras un login exitoso (mismo punto donde hoy se configuran los perfiles SMB si faltan vía `configurar_perfiles_smb_si_faltan`). Esto garantiza que, incluso si la app crashea con un perfil SFTP activo, no sobrevive más allá del siguiente arranque.

---

## Sección 2: Frontend — `bifrost-transfer/src/main.py`

### Botón y diálogo de conexión

Dentro de `_build_copy_content`, junto al `pick_row` existente (ambas ramas desktop/web):

```python
sftp_btn = btn_secondary("🌐 SFTP", on_click=lambda e: _open_sftp_dialog())
pick_row.controls.append(sftp_btn)
```

Nuevo diálogo `_build_sftp_connect_dialog` (mismo patrón visual que el diálogo de "Renew credentials"): campos Host, Port (default `"22"`), Username, Password + botón "Connect" con spinner inline y texto de error (no bloqueante, permite reintentar sin cerrar el diálogo).

### Estado de sesión y ciclo de vida del perfil

```python
sftp_state = {"perfil": None}
```

- **Al conectar con éxito**: `crear_perfil_rclone_sftp(...)` → `rclone_lsd(perfil, "")` para validar → si OK, `sftp_state["perfil"] = perfil` y se abre un modal (mismo patrón que `show_local_fs_modal`) envolviendo `build_rclone_browser(page, perfil_rclone=perfil, on_select=..., lab_filter_enabled=False)`.
- **Al seleccionar carpeta**: `origen_tf.value = f"{sftp_state['perfil']}:{path}"`, se cierra el modal, y aparece una etiqueta "🌐 Connected to `user@host`" con un botón ✕ (Disconnect) junto al campo origen.
- **Disconnect** (botón ✕): `backend.eliminar_perfil_rclone(sftp_state["perfil"])`, limpia `origen_tf.value`, `sftp_state["perfil"] = None`, oculta la etiqueta.
- **Al pulsar `on_back()`** (salir de la vista de copy): si `sftp_state["perfil"]` no es `None`, se borra igual que en Disconnect, antes de navegar atrás.

`bifrost-transfer` no tiene un flujo de "logout" explícito (solo navegación `on_back` entre vistas) — el `on_back` cubre el caso de salir de la vista de copy, y el barrido al login (ver abajo) cubre cualquier resto de una sesión anterior (cierre de la app sin pasar por `on_back`, crash, etc.).

---

## Manejo de errores

| Caso | Mensaje |
|---|---|
| Host inalcanzable / timeout | "No se pudo conectar con `host:port`. Verifica la dirección y que el servidor sea accesible desde tu red." |
| Credenciales rechazadas | "Usuario o contraseña incorrectos." |
| Otro fallo de rclone | Se muestra el stderr crudo en el diálogo (igual que hoy con errores de copy en el log) |
| Fallo de `rclone copy` con origen SFTP ya en curso | Sin rama especial — mismo manejo que hoy (el proceso rclone gestiona reintentos/errores de red igual que con SMB) |

En todos los casos de error de conexión, si `crear_perfil_rclone_sftp` ya escribió la sección antes de que fallara la validación, se borra inmediatamente (`eliminar_perfil_rclone`) — no se deja un perfil con credenciales inválidas o no confirmadas en disco.

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `shared/bifrost_backend/backend.py` | Nueva sección "GESTIÓN SFTP (ORIGEN EFÍMERO)": `crear_perfil_rclone_sftp`, `eliminar_perfil_rclone`, `limpiar_perfiles_rclone_con_prefijo` |
| `bifrost-transfer/src/main.py` | Botón "🌐 SFTP" en `pick_row` (desktop y web), `_build_sftp_connect_dialog`, `sftp_state`, modal de browser reutilizando `build_rclone_browser`, etiqueta "Connected" + Disconnect, hook de cleanup en `on_back`, llamada a `limpiar_perfiles_rclone_con_prefijo` tras login |
| `CLAUDE.md` | Nuevo gotcha en "Convenciones y gotchas críticas": el origen SFTP usa un perfil rclone temporal (`sftp-src-<random>`) que se borra en Disconnect/`on_back` y se barre por prefijo al login; explicar por qué (decisión de seguridad, ver este spec) para que quede documentado el patrón junto al resto de gotchas de `main.py`/`backend.py` |
| `README.md` | Actualizar la descripción de `bifrost-transfer` (línea ~8, "Upload data from network shares (SMB/CIFS) or local folders...") para mencionar SFTP como tercer origen soportado |

---

## Restricciones y gotchas

- El browser (`build_rclone_browser` / `rclone_lsd`) solo lista carpetas, no ficheros individuales — el origen SFTP soporta selección de carpeta, no de fichero suelto (misma limitación que ya tiene el browser de destino).
- La contraseña SFTP se ofusca con `rclone obscure`, nunca se guarda en claro; sigue siendo reversible (no es cifrado real), de ahí la limpieza agresiva del perfil.
- No hay suite de tests automatizada en este repo (ver `CLAUDE.md`); validación manual con `flet run` (desktop) y `flet run --web` / `BIFROST_CLUSTER=1` (web), cubriendo:
  1. Conexión correcta → navegación → selección → copy completo a MinIO con tags.
  2. Credenciales incorrectas → mensaje correcto, sin perfil huérfano en `rclone.conf`.
  3. Host inalcanzable/timeout → mensaje correcto.
  4. Disconnect manual → confirmar que la sección desaparece de `rclone.conf`.
  5. Salir de la vista de copy sin desconectar → confirmar cleanup en `on_back`.
  6. Simular crash (matar el proceso con perfil activo) → reiniciar app → confirmar que el barrido de login elimina la sección huérfana.
  7. Repetir en modo desktop y modo web.
