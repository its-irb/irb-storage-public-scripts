# Arquitectura

## Problema que resuelve

Los investigadores del IRB Barcelona necesitan mover datos entre carpetas de
red (SMB/CIFS), servidores SFTP o máquinas locales y el servidor MinIO S3 del
instituto, y etiquetar esos datos con metadatos gestionados por laboratorio.
BIFROST proporciona dos aplicaciones de escritorio (y una variante web para el
clúster) que encapsulan ese flujo sin requerir conocimientos de S3 ni de
rclone.

## Componentes y responsabilidades

| Componente | Responsabilidad |
|---|---|
| `bifrost-transfer` | Copiar datos a buckets S3 con verificación de integridad, aplicar perfiles de metadatos, gestionar tags existentes (Tag Manager), ofrecer modo web para el clúster (Open OnDemand). |
| `bifrost-mount` | Montar rutas de buckets S3 como unidades locales en Windows/macOS/Linux. |
| `shared/bifrost_backend` | Toda la lógica no-UI: autenticación (LDAP), credenciales temporales (STS) y token de sesión, perfiles y ejecución de rclone, acceso SMB/CIFS, tagging S3 vía boto3, autoupdate, helpers de concurrencia UI y constantes compartidas. Organizado en `common/`, `mount/` y `transfer/`; `backend.py` es una fachada que reexporta la API pública. |
| `shared/bifrost_frontend` | Tema (paleta, fuentes), componentes Flet reutilizables y las vistas comunes a las dos apps (actualización, login, selección de MinIO, renovación de credenciales), para que ambas apps se vean y se comporten igual. `frontend.py` es una fachada que reexporta todo. |

## Por qué está estructurado así

- **Backend común en un wheel local (`bifrost-shared`)**: las dos apps son
  gemelas en su flujo base (login LDAP → MinIO → STS → acción). Extraer el
  backend evita duplicar la lógica crítica (rclone, STS, SMB) en dos
  `main.py`. El `pyproject.toml` de cada app referencia
  `bifrost-shared @ file:///__BUILDPATH__/shared`; el mecanismo `__BUILDPATH__`
  permite que tanto CI como builds locales sustituyan el placeholder por la
  ruta real del wheel generado. Por eso las apps versionan una plantilla
  (`pyproject-template.toml`) y el `pyproject.toml` efectivo es local.
- **`APP_INFO["flavour"]` en cada app**: el backend es un único paquete
  compartido por las dos apps; el flavour le permite resolver rutas de assets
  empaquetados (`bifrost-<flavour>/src/assets/bin/`) en desarrollo sin
  parámetros extra.
- **Fachadas `backend.py` y `frontend.py`**: el backend y el frontend se
  dividieron en módulos por área, pero las apps siguen usando `backend.X` y
  `from bifrost_frontend.frontend import *`. Las fachadas reexportan los
  nombres para que esa división no obligue a cambiar las llamadas (así lo
  indican sus docstrings: "fachada de compatibilidad").
- **Vistas compartidas en `shared/bifrost_frontend/views/`**: login, selección
  de MinIO y renovación de credenciales eran casi idénticas en las dos apps;
  ahora hay una sola versión y lo que cambia entre apps se pasa como parámetro
  (`no_ldap`, `is_web`, `prefill_user`, `log_event`, `write_log`,
  `done_message`). Un arreglo en esas vistas se hace una vez para las dos apps.
- **Backend que importa del frontend**: solo `safe_thread`
  (`common/ui_helpers.py`) importa `show_dialog` y `C_ERROR` de
  `bifrost_frontend.frontend`, para mostrar en un diálogo las excepciones no
  capturadas de los hilos. El import es diferido (dentro de la función) para
  evitar un import circular. Es un compromiso consciente (no es un backend
  totalmente desacoplado); separarlo exigiría rediseñar la propagación de
  errores.
- **`IS_WEB` calculado solo en el `main.py` de transfer**: depende de
  `__name__ != "__main__"` (Hypercorn importa `main.py`) y `main()` lo
  actualiza con `page.web`, así que no puede recalcularse en otro módulo. Los
  módulos que se sacaron de `main.py` y lo leen declaran `IS_WEB = False` y
  `_propagar_is_web()` les copia el valor real al importar y cada vez que
  `main()` lo cambia; así su código se pudo mover sin modificarlo.
- **Binarios empaquetados**: `rclone` (y `fuse-t` en macOS para mount) viajan
  dentro del ejecutable, de modo que el usuario final no instala nada. La
  excepción es WinFsp en Windows: incluye un driver de kernel y no puede
  empaquetarse, por lo que `bifrost-mount` detecta su ausencia y ofrece su
  instalación automática.
- **Modo web solo en transfer**: el caso de uso del clúster (Open OnDemand) es
  subir datos; el montado local no tiene sentido ahí. De ahí que el flujo
  compartido termine en `view_copy` y que transfer tenga mucho más código
  propio (`web_session.py` y las vistas `shares`, `rclone_browser`,
  `local_fs`, `copy` y `tag_manager`).

## Flujo completo (desktop)

```text
view_update (comprueba release)
  → view_login   (valida credenciales contra LDAP; BIFROST_NO_LDAP=1 se salta la validación)
  → view_minio   (selección de servidor MinIO / perfil rclone)
  → view_credentials (obtiene credenciales STS temporales; reutiliza si quedan >3 días)
  → view_mount (mount) | view_copy (transfer; con view_shares previa en clúster)
```

Las credenciales STS se reutilizan si les quedan más de 3 días y son del
usuario que ha iniciado sesión; si no, se renuevan automáticamente por 7 días
(`STS_RENEWAL_THRESHOLD_DAYS` y `STS_AUTO_RENEWAL_DAYS` en
`bifrost_backend.common.constants`). Las vistas de montaje y de copia permiten
además renovarlas a mano (botón "🔑 Renew credentials", de 1 a 30 días).

## Límites y consecuencias de modificarlos

- **`config.py` top-level por app**: el backend y el frontend compartidos hacen
  `from config import APP_INFO`; mover `config.py` o convertirlo en paquete
  rompe la resolución de imports en todas las apps.
- **Las vistas no importan `main`**: `main.py` importa las vistas, así que el
  import inverso sería circular. Lo que necesitan a la vez una vista y
  `main.py` vive en `shared/` (p. ej. las constantes `STS_*` y `NO_LDAP` en
  `bifrost_backend.common.constants`) o en un módulo propio de la app
  (`session_log.py`, `web_session.py`).
- **`_propagar_is_web()`**: si un módulo nuevo de transfer lee `IS_WEB` y no se
  añade a la tupla de `_propagar_is_web()`, se comportará siempre como
  escritorio, sin dar ningún error.
- **`ui_call` como única vía de mutación UI desde hilos**: relajar esta regla
  reintroduce el `IndexError` del diff walker de Flet (ver
  [frontend.md](frontend.md), sección del bug).
- **`TAG_PROFILES`/`LAB_ACRONYMS` en `meta_fields.py` (solo transfer)**:
  formulario de copia y Tag Manager derivan de ahí y `LAB_ACRONYMS` debe
  coincidir con los tags `acronym` reales de los buckets; duplicar o divergir
  rompe el filtro por laboratorio y la detección de perfil.
- **Perfiles rclone con prefijo `sftp-src-`**: son efímeros por diseño y se
  barren tras cada login; cualquier código nuevo que cree perfiles debe
  garantizar un ciclo de vida equivalente.
- **Doble vía de listado**: el browser S3 destino usa `rclone_lsd` (solo
  carpetas) y el SFTP usa `rclone_lsjson` (carpetas + ficheros); el listado
  completo sobre MinIO/HDD es lento y esa es la razón documentada de la
  asimetría.

## Motivaciones no verificables desde el repositorio

- Por qué se eligió Hypercorn/Flet como stack ASGI frente a alternativas.
- Criterios históricos de la elección de rclone como motor único
  (mount/transfer/listing).
- Procedencia exacta de la lista de perfiles de metadatos frente a los
  requisitos de los laboratorios.

Estas cuestiones requieren confirmación humana; no documentarlas como hechos.
