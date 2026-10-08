# Build, CI y releases

## Prerrequisitos

**Para desarrollar y ejecutar las apps:**

- **Python ≥ 3.11** (`requires-python = ">=3.11"` en el `pyproject.toml` de cada
  app y en `shared/`). La CI builda con **3.12**.
- **uv** (gestor de entornos/dependencias) — es lo que hacen la CI y
  `build-macos.sh`:

  ```bash
  pip install uv
  ```
- **VPN de Nexica (Forticlient)** — necesaria para **ejecutar** las apps (LDAP
  y MinIO); no la necesitan los builds.
- `flet` (0.84.0) y el resto de dependencias van **congeladas** en el
  `pyproject.toml` de cada app y las instala `uv sync`. En Linux la plantilla
  añade `flet-web` (transfer) o `flet-cli`/`flet-desktop` (mount) para el venv
  del clúster.

**Para empaquetar localmente:**

- **macOS**: **Xcode** (flet/Flutter compila el `.app` con esa toolchain).
- **Windows**: **Node.js** (lo requiere `flet build windows`; la CI usa
  Node 24), **Inno Setup 6** solo para empaquetar el instalador, y
  **Git Bash** (los scripts de assets son bash).
- **Los binarios `rclone` y `fuse-t` NO están versionados en el repo**:
  `src/assets/bin/` y `frameworks/` están gitignores (solo se versionan los
  `.keep`). Hay que descargarlos con los scripts
  `shared/*-assets-downloader.sh` (ver «Primera vez» y «Empaquetado»).

## Entorno de desarrollo

Pasos por app (idénticos para `bifrost-mount/` y `bifrost-transfer/`), desde
la carpeta de la app:

### Primera vez

1. Generar el `pyproject.toml` local desde la plantilla (el `pyproject.toml`
   **no está versionado**; solo `pyproject-template.toml`):

   ```bash
   cp pyproject-template.toml pyproject.toml
   sed -i '' "s|__BUILDPATH__|${PWD}/..|g" ./pyproject.toml   # macOS
   sed -i "s|__BUILDPATH__|${PWD}/..|g" ./pyproject.toml      # Linux / Git Bash
   ```

2. Sincronizar el entorno virtual (instala las dependencias y
   `bifrost-shared` desde la ruta local):

   ```bash
   uv sync
   ```

3. **Descargar los binarios** (obligatorio; no vienen en el repo).

   Los scripts escriben en **rutas relativas** (`./assets/bin/`,
   `./assets/fonts/` y, en mount/macOS, `../frameworks/`), por lo que
   **siempre** hay que ejecutarlos desde la carpeta `src/` de la app, y
   **cada app descarga su propia copia**: se repite el comando desde la
   `src/` de **cada aplicación** que vayas a usar o construir, incluso si el
   comando es el mismo.

    `bifrost-mount` en macOS (dentro de `bifrost-mount/`):

    ```bash
    cd src
    bash ../../shared/macos-assets-downloader.sh   # rclone + fuse_t.framework
    ```

    `bifrost-transfer` en macOS (dentro de `bifrost-transfer/`):

    ```bash
    cd src
    bash ../../shared/macos-rclone-downloader.sh   # rclone
    ```

    Windows, Git Bash (dentro de cada app — `bifrost-mount/` y
    `bifrost-transfer/` — repitiendo el paso en las dos):

    ```bash
    cd src
    bash ../../shared/windows-assets-downloader.sh   # rclone.exe
    ```

    Linux / clúster (dentro de cada app — `bifrost-mount/` y
    `bifrost-transfer/` — repitiendo el paso en las dos):

    ```bash
    cd src
    bash ../../shared/linux-assets-downloader.sh    # rclone
    ```

    Cada script descarga en `./assets/bin/` el binario de rclone (versión
    `1.72.1`, fijada en los scripts) y la fuente
    `NotoColorEmoji-noflags.ttf` en `./assets/fonts/`;
    `macos-assets-downloader.sh` añade además
    `../frameworks/fuse_t.framework` (versión `1.0.49`, solo
    `bifrost-mount` en macOS).

    En macOS la arquitectura de `rclone` se auto-detecta con `uname -m`
    (`arm64` en Apple Silicon, `amd64` en Intel) y se puede forzar con la
    variable `RCLONE_ARCH`. La CI la fija explícitamente: `arm64` en el job
    ARM y `amd64` en el job Intel (stopgap hasta nov-2026).

### Activar y ejecutar (cada vez)

```bash
source .venv/bin/activate            # macOS / Linux
# Windows:
#   PowerShell:  .\.venv\Scripts\Activate.ps1
#   CMD:         .\.venv\Scripts\activate.bat
#   Git Bash:    source .venv/Scripts/activate

flet run
```

Flags útiles:

```bash
flet run --customuser     # login con otro usuario
flet run --update         # forzar autoupdate
flet run --web            # (solo transfer) modo web para desarrollo local
BIFROST_CLUSTER=1 python src/main.py --web   # (solo transfer) simular OOD
```

### Trabajar con código compartido

Tras modificar `shared/` (o cambiar de rama con `shared/` diferente):

```bash
uv sync --reinstall-package bifrost-shared
```

Sin esto, `uv`/Python pueden seguir usando la versión del paquete ya
instalada en `.venv`. Alternativa manual (sin uv), ver
[backend.md](backend.md):

```bash
cd shared
python -m build .
pip install dist/bifrost_shared-*.whl
```

### Actualizar dependencias

Las deps están congeladas en el `pyproject.toml` de cada app. Para añadir o
subir una (ejecutar dentro de la app):

```bash
uv add <package>
```

(La documentación heredada menciona un flujo con `src/pip-requirements.txt`;
ese fichero ya no existe en el repositorio — ver sección «Pendiente».)

## Empaquetado (builds locales)

`flet build` usa los parámetros del `pyproject.toml` de la app. Prerrequisito
común: `pyproject.toml` local generado desde la plantilla con
`__BUILDPATH__` sustituido, venv sincronizado y **assets descargados**.

| Entorno | Salida |
|---|---|
| macOS local | `dist/<app>.app` |
| Windows local | `dist/<app>/` + paso manual de Inno Setup para el instalador |
| Linux (clúster) | Sin empaquetado: `bifrost-transfer` corre **desde código** en modo web (Open OnDemand, `BIFROST_CLUSTER=1`) |

```bash
# macOS (desde la carpeta de la app)
./build-macos.sh
```

```powershell
# Windows (desde la raíz del repo)
.\build-windows.ps1 -app bifrost-mount    # o -app bifrost-transfer (por omisión, transfer)
```

**`build-macos.sh`** automatiza: plantilla → `pyproject.toml` (con
`__BUILDPATH__` = `$(pwd)/..`), versión `2.0.0.dev` (en el `pyproject.toml` y
en `version.py`), limpieza de `dist/`/`build/`, `pip install uv`, `uv sync`,
descarga de assets y `flet build macos -o ./dist`. En `bifrost-mount` copia
además `frameworks/fuse_t.framework` a
`dist/bifrost-mount.app/Contents/Frameworks/` (paso sin el que el montado en
macOS no funciona).

**`build-windows.ps1`** automatiza: regenerar `pyproject.toml` desde la
plantilla, descargar rclone (`windows-assets-downloader.sh`),
`uv sync --reinstall-package bifrost-shared` y `flet build windows`. **No**
ejecuta Inno Setup: el instalador se empaqueta aparte, con

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" `
  /DAppVersion=<version> /DAppName=<app> /DBranchSuffix=<sufijo> <app>\installer.iss
```

generando `installer/<AppName>-<sufijo>-windows.exe`. (La firma del instalador
solo la hace la CI; ver abajo.)

**Linux**: no existe build binario — el modo web del clúster importa
`main.py` como módulo ASGI (Hypercorn) con un venv creado desde la plantilla
(de ahí las dependencias `flet-web`/`flet-cli`/`flet-desktop` marcadas para
`platform_system == "Linux"`).

## CI (`.github/workflows/main.yml`)

- **Triggers**: push a `main`, `release`, `develop`, `feature/**` — solo con
  cambios en `bifrost-transfer/**`, `bifrost-mount/**`, `shared/**` o el
  propio workflow—, además de `workflow_dispatch` (manual).
- **Toolchain**: Python **3.12** (`setup-python`), `uv` vía `pip install uv`,
  **Node 24** (`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`; necesario para
  `flet build windows`), y en Windows `PYTHONUTF8=1` y long paths activados.
- **Versionado**: `1.0.<run_number>`. Se genera el `pyproject.toml` desde la
  plantilla con `__BUILDPATH__` = workspace, se reescribe su `version`
  (la de la plantilla es `2.0.0`) y se escribe
  `__version__ = "1.0.<run_number>"` en `src/version.py`.
- **Job `build-macos`** (matriz por app, runner `macos-latest`, Apple
  Silicon): descarga assets (mount: `macos-assets-downloader.sh`;
  transfer: `macos-rclone-downloader.sh`, con `RCLONE_ARCH=arm64` para
  determinismo), `uv sync`, `flet build macos --output dist --no-rich-output`
  (con `echo "y" |` para autoconfirmar); en mount copia `fuse_t.framework` al
  bundle; genera un **DMG** (action `create-dmg`) → artefacto
  `bifrost-<flavour>-macos.dmg`.
- **Job `build-macos-intel`** (matriz por app, runner `macos-14`): copia del
  job anterior usando los mismos scripts de descarga con `RCLONE_ARCH=amd64`
  → artefacto `bifrost-<flavour>-macos-intel.dmg`. **Stopgap
  hasta el 2-nov-2026** (fecha en la que GitHub retira el runner `macos-14`,
  el último Intel hosted): lleva `continue-on-error: true` para que, tras esa
  fecha, su fallo no bloquee la release; hay que eliminar el job por completo
  en el follow-up de esa fecha.
- **Job `build-windows`** (matriz por app): descarga rclone, `uv sync`,
  `uv run flet build windows --output dist --no-rich-output -v`,
  **Inno Setup** (`ISCC.exe` sobre `installer.iss` con
  `/DBranchSuffix`, `/DAppVersion=1.0.<run_number>`, `/DAppName=<app>`) →
  `installer/*.exe`, y **firma el instalador** con `signtool` (certificado
  PFX desde los secrets del repo `IRBCODESIGNING` /
  `IRBCODESIGNING_PASSWORD`, con timestamp de Digicert).
- **Job `release`** (solo en `main` y `release`): descarga los artefactos de
  los tres jobs de build (por eso su `needs` incluye también
  `build-macos-intel`) y publica una release de GitHub con tag
  `v1.0.<run_number>` que contiene:
  - macOS: `bifrost-<flavour>-macos.dmg` (Apple Silicon) y
    `bifrost-<flavour>-macos-intel.dmg` (Intel, stopgap hasta nov-2026)
  - Windows: `bifrost-<flavour>/installer/bifrost-<flavour>-<rama>-windows.exe`
    (firmado)

  De estas releases descarga el autoupdate de las apps
  (`backend.download_new_binary()`): en macOS elige el sufijo según la
  arquitectura de la máquina (`platform.machine()`: arm64 → `-macos.dmg`,
  x86_64 → `-macos-intel.dmg`); solo los Macs Intel con release pre-stopgap
  necesitan una instalación manual del `-macos-intel.dmg`.

## Política de validación

**No hay suite de tests automatizada.** Los cambios se validan ejecutando las
apps manualmente (`flet run`, y en su caso `flet run --web`). Las
funciones críticas a probar manualmente tras un cambio:

- login y renovación de credenciales STS;
- copy completa + check de integridad;
- Tag Manager (aplicar a fichero, carpeta y prefijo de bucket);
- reconexión de pestaña en modo web durante una copia;
- mount/unmount (y detección de WinFsp en Windows).

## Pendiente de verificar

- El flujo de regeneración de `src/pip-requirements.txt` (mencionado en la
  documentación heredada) no corresponde al estado actual del repo: no existe
  ese fichero en `bifrost-transfer/src/`. Confirmar con el equipo si el flujo
  vigente es únicamente `uv add` sobre el `pyproject.toml` por app.
- La documentación antigua (versiones previas de CLAUDE.md y README.md) citaba un script
  `build-local.ps1` que **ya no existe**; el script actual de build local de
  Windows es `build-windows.ps1`.
- La documentación heredada afirma que «el repo trae los binarios bajo
  `bifrost-*/src/assets/bin/`» y que la CI hace `flet build linux` para el
  clúster: en el estado actual del repo los binarios están gitignores (se
  descargan con los scripts de `shared/`) y el workflow **no tiene job de
  Linux** (el clúster corre el modo web desde código).
