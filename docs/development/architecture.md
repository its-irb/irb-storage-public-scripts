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
| `shared/bifrost_backend` | Toda la lógica no-UI: autenticación (LDAP), credenciales temporales (STS), perfiles y ejecución de rclone, acceso SMB/CIFS, tagging S3 vía boto3, autoupdate y helpers de concurrencia UI. |
| `shared/bifrost_frontend` | Paleta de colores y componentes Flet reutilizables para que ambas apps se vean idénticas. |

## Por qué está estructurado así

- **Backend común en un wheel local (`bifrost-shared`)**: las dos apps son
  gemelas en su flujo base (login LDAP → MinIO → STS → acción). Extraer el
  backend evita duplicar la lógica crítica (rclone, STS, SMB) en dos
  `main.py`. El `pyproject.toml` de cada app referencia
  `bifrost-shared @ file:///__BUILDPATH__/shared`; el mecanismo `__BUILDPATH__`
  permite que tanto CI como builds locales sustituyan el placeholder por la
  ruta real del wheel generado. Por eso las apps versionan una plantilla
  (`pyproject-template.toml`) y el `pyproject.toml` efectivo es local.
- **`APP_INFO["flavour"]` en cada app**: el backend es un único módulo
  compartido; el flavour le permite resolver rutas de assets empaquetados
  (`bifrost-<flavour>/src/assets/bin/`) en desarrollo sin parámetros extra.
- **Backend que importa del frontend**: `backend.py` usa `show_dialog` y
  `C_ERROR` de `bifrost_frontend.frontend` para presentar errores no
  recuperables sin devolver códigos de error por toda la pila. Es un
  compromiso consciente (no es un backend desacoplado); separarlo exigiría
  rediseñar la propagación de errores.
- **Binarios empaquetados**: `rclone` (y `fuse-t` en macOS para mount) viajan
  dentro del ejecutable, de modo que el usuario final no instala nada. La
  excepción es WinFsp en Windows: incluye un driver de kernel y no puede
  empaquetarse, por lo que `bifrost-mount` detecta su ausencia y ofrece su
  instalación automática.
- **Modo web solo en transfer**: el caso de uso del clúster (Open OnDemand) es
  subir datos; el montado local no tiene sentido ahí. De ahí que el flujo
  compartido termine en `view_copy` y que el tamaño de `transfer/src/main.py`
  sea muy superior.

## Flujo completo (desktop)

```text
view_update (comprueba release)
  → view_login   (valida credenciales contra LDAP; BIFROST_NO_LDAP=1 se salta la validación)
  → view_minio   (selección de servidor MinIO / perfil rclone)
  → view_credentials (obtiene credenciales STS temporales; reutiliza si quedan >3 días)
  → view_mount (mount) | view_copy (transfer; con view_shares previa en clúster)
```

Las credenciales STS se renuevan automáticamente 7 días antes de expirar por
debajo del umbral de 3 días (constantes en cada `main.py`).

## Límites y consecuencias de modificarlos

- **`config.py` top-level por app**: el backend hace `from config import
  APP_INFO`; mover `config.py` o convertirlo en paquete rompe la resolución de
  imports en todas las apps.
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
