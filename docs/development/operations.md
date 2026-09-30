# Operación: variables de entorno, autoupdate y logs

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal de producción OOD; flujo CIFS/shares del cluster). |
| `BIFROST_NO_LDAP=1` | ambas | Salta la validación LDAP en el login. Para máquinas sin acceso a LDAP pero con acceso a MinIO (p. ej. IVIS). El usuario igualmente introduce usuario+contraseña (necesarios para STS). El badge del header muestra `DESKTOP (NO LDAP)`. En Windows se define como variable de sistema (ver abajo) para que aplique a todos los usuarios. |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar el `rclone` empaquetado (`FLET_ASSETS_DIR/bin/`). |
| `FLET_APP_STORAGE_TEMP` | ambas | La setea Flet; usada para depurar la localización de binarios. |

```powershell
# BIFROST_NO_LDAP como variable de sistema de Windows (aplica a todos los usuarios)
setx BIFROST_NO_LDAP 1 /M
```

## Autoupdate

Cuando existe una release nueva de la app en el repositorio, la app pregunta
al usuario si quiere actualizarse y descarga el binario nuevo desde las
releases de GitHub.

- Lógica backend: `backend.check_update_version()`,
  `backend.should_check_for_updates()`, `backend.get_update_file_suffix()`,
  `backend.download_new_binary()`.
- Vista: `view_update` es la primera vista del flujo; para forzar la
  comprobación en desarrollo:

  ```bash
  flet run --update
  ```
- Versionado: `1.0.<run_number>` (ver [build-and-ci.md](build-and-ci.md)).

## Logs

- **Desktop**: cada `main.py` configura un log persistente:
  `~/bifrost-mount-logs/` en `bifrost-mount` y `~/bifrost-logs/` en
  `bifrost-transfer` (la nomenclatura no sigue el patrón `<flavour>`).
- **Modo web**: al terminar cada copy/check, `_autosave_log()` vuelca el
  buffer de la sesión a `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log` en el
  servidor OOD. El buffer en memoria está capeado a 5000 líneas y la
  reconexión solo replayea 200, por lo que el log completo solo existe en
  disco.

## Seguridad

- La contraseña LDAP **nunca** se persiste en el modo web (`_WEB_SESSIONS`
  guarda estado de sesión pero no credenciales).
- Los perfiles rclone SFTP efímeros (`sftp-src-*`) almacenan la contraseña
  ofuscada con `rclone obscure` y se eliminan al final de la sesión y en cada
  login (ver [frontend.md](frontend.md)).
- No incluir valores sensibles (credenciales, tokens, connection strings) en
  documentación, commits ni artefactos; usar marcadores.

## Zona legacy

`old/` contiene `backend-old.py` y `minio-sts-credentials-request.py`:
scripts legacy, fuera de uso. No importar de ahí ni documentarlos como
activos.
