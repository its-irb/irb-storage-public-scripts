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
   ```powershell
   # Windows (PowerShell), dentro de la carpeta de la app. El fichero tiene que quedar en UTF-8 sin BOM:
   # con Set-Content -Encoding utf8, PowerShell 5.1 añade un BOM y flet run falla con
   # "TOMLDecodeError: Invalid statement (at line 1, column 1)".
   $utf8 = New-Object System.Text.UTF8Encoding $false
   $toml = [IO.File]::ReadAllText("$PWD\pyproject-template.toml", $utf8).Replace('__BUILDPATH__', ((Resolve-Path ..).Path -replace '\\','/'))
   [IO.File]::WriteAllText("$PWD\pyproject.toml", $toml, $utf8)
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
    ARM y `amd64` en el job Intel.

### Activar y ejecutar (cada vez)

```bash
source .venv/bin/activate            # macOS / Linux
# Windows:
#   PowerShell:  .\.venv\Scripts\Activate.ps1
#   CMD:         .\.venv\Scripts\activate.bat
#   Git Bash:    source .venv/Scripts/activate

flet run
```

En Windows, `.\build-windows.ps1 -app <app> -run` desde la raíz del repo hace
los pasos de «Primera vez» (genera el `pyproject.toml`, descarga los assets y
sincroniza el venv reinstalando `bifrost-shared`) y lanza `uv run flet run` en
la carpeta de la app, sin tener que activar el venv (ver «Empaquetado»).

Flags útiles:

```bash
python src/main.py --update   # fuerza la comprobación del autoupdate (flet run no deja pasarle argumentos)
flet run --web            # (solo transfer) modo web para desarrollo local
BIFROST_CLUSTER=1 python src/main.py --web   # (solo transfer) simular OOD
```

- `--update` se pasa con `python src/main.py --update`, desde la carpeta de la
  app: `flet run` rechaza cualquier argumento que no sea suyo (`unrecognized
  arguments: --update`). Fuerza la comprobación aunque la versión sea la de
  desarrollo (`0.0.0.dev`), así que cualquier release es más nueva y sale la
  pantalla de actualización (salvo en Linux o con `BIFROST_CLUSTER=1`, donde no
  se comprueba nunca). **"Update now" instala la release de verdad** (en macOS
  sustituye `/Applications/bifrost-<app>.app` y pide la contraseña de
  administrador); para ver solo la pantalla, "Continue anyway".
  `check_update_version()` sigue sin usar `force_update`: el bloque que simula la
  versión `999.999.999` está comentado.
- El campo de usuario del login es siempre editable; no hace falta ningún
  flag para entrar con otro usuario.
- Con Flet 0.84, `flet run --web` falla con
  `ModuleNotFoundError: No module named 'flet_desktop'` si en ese venv nunca
  se ha ejecutado `flet run` en modo escritorio (`flet_cli` importa
  `flet_desktop` también en modo web). Además instala en el venv `flet-web`,
  `fastapi`, `uvicorn` y otros paquetes, y puede cambiar versiones fijadas
  (actualizó `httptools`). Alternativa sin el CLI de Flet, desde
  `bifrost-transfer/`: sirve la app en el puerto 8000 (cámbialo con
  `FLET_SERVER_PORT`) y hay que abrir `http://localhost:8000` a mano. Flet
  instala `flet-web` automáticamente si falta (las dependencias de la app solo
  lo incluyen en Linux), pero instala la última FastAPI, que ya no acepta el
  `openapi_prefix` que le pasa `flet-web` 0.84, y el arranque falla con
  `TypeError: FastAPI.__init__() got an unexpected keyword argument
  'openapi_prefix'`. Antes hay que instalar las versiones fijadas (las que usa
  `uv.lock` en el clúster), con el venv **de transfer** activado (no el de
  mount: Flet instalaría los paquetes en el venv equivocado):

```bash
uv pip install --python .venv/bin/python "flet-web==0.84.0" "fastapi==0.143.0"
FLET_FORCE_WEB_SERVER=true python src/main.py --web
```

  Un `uv sync` posterior (también `uv sync --reinstall-package bifrost-shared`)
  quita esos dos paquetes, porque en las dependencias de la app son solo de
  Linux: hay que volver a instalarlos antes de la siguiente prueba.

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
| Windows local | `<app>/build/windows/` (`build-windows.ps1` llama a `flet build windows` sin `--output`; la CI usa `--output dist`) + paso manual de Inno Setup para el instalador |
| Linux (clúster) | Sin empaquetado: `bifrost-transfer` corre **desde código** en modo web (Open OnDemand, `BIFROST_CLUSTER=1`) |

```bash
# macOS (desde la carpeta de la app)
./build-macos.sh
```

```powershell
# Windows (desde la raíz del repo; por omisión, -app bifrost-mount)
.\build-windows.ps1 -app bifrost-transfer        # flet build windows
.\build-windows.ps1 -app bifrost-transfer -run   # flet run, para desarrollar
```

**`build-macos.sh`** automatiza: plantilla → `pyproject.toml` (con
`__BUILDPATH__` = `$(pwd)/..`), versión `0.0.0.dev` (en el `pyproject.toml` y
en `version.py`; el script **sobrescribe** `version.py`, así que para probar el
autoupdate con una versión antigua hay que cambiarla en el script), limpieza de `dist/`/`build/`, `pip install uv`, `uv sync`,
descarga de assets y `flet build macos -o ./dist`. En `bifrost-mount` copia
además `frameworks/fuse_t.framework` a
`dist/bifrost-mount.app/Contents/Frameworks/` (paso sin el que el montado en
macOS no funciona).

**`build-windows.ps1`** automatiza: regenerar `pyproject.toml` desde la
plantilla (`__BUILDPATH__` = ruta absoluta de la raíz del repo, con barras
`/`, la del propio script), descargar rclone (`windows-assets-downloader.sh`),
`uv sync --reinstall-package bifrost-shared` y, según `-run`,
`uv run flet run` (con el venv de la app, aunque haya otro activado) o
`flet build windows` (con el `flet` que esté en el PATH, así que hay que tener
activado el venv de la app). Usa rutas relativas a la raíz del repo, así que
hay que lanzarlo desde allí. Si no se indica `-app`, usa `bifrost-mount`. **No**
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
  propio workflow—, además de `workflow_dispatch` (manual). Todas compilan y
  suben artefactos; **solo `main` publica releases** (la rama `release` ya no).
- **Toolchain**: Python **3.12** (`setup-python`), `uv` vía `pip install uv`,
  **Node 24** (`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`; necesario para
  `flet build windows`), y en Windows `PYTHONUTF8=1` y long paths activados.
- **Versionado** (SemVer `MAYOR.MENOR.PARCHE`, una sola versión para las dos
  apps): el job `version` ejecuta `.github/scripts/next_version.py version` y
  los demás jobs usan sus salidas (`version`, `base`, `is_release`). Lee los
  commits desde el tag `vX.Y.Z` más alto (sin los «Merge pull request», pero sí
  los commits que traen dentro):

  | Commits desde la última release | Siguiente versión |
  |---|---|
  | `feat!:` (cualquier tipo con `!`) o `BREAKING CHANGE:` en el cuerpo | MAYOR (`1.4.2` → `2.0.0`) |
  | algún `feat` | MENOR (`1.4.2` → `1.5.0`) |
  | solo `fix`, `perf`, `revert` o `build` | PARCHE (`1.4.2` → `1.4.3`) |
  | solo `docs`, `style`, `refactor`, `test`, `ci` o `chore` | ninguna |
  | `Release-As: X.Y.Z` en el cuerpo de un commit (manda el más reciente) | exactamente esa |

  Si llegan varios tipos, manda el más fuerte: una sola versión por push.
  - **En `main` con versión nueva**: `version` = `base` = `X.Y.Z` e
    `is_release=true`; el job `release` la publica.
  - **En el resto** (otras ramas, o `main` sin commits que saquen versión):
    `version` = `<última release>.<run_number>` (p. ej. `1.1.0.412`), `base` =
    la última release, `is_release=false`; solo artefactos.
  - `version` se escribe en `src/version.py` y en el `AppVersion` de Inno
    Setup; `base` en el `version` del `pyproject.toml` y en
    `flet build --build-version`, con `--build-number <run_number>`.

  Por qué así:
  - **El número sale de los commits** (que commitlint ya obliga a escribir con
    tipo), así que tiene significado y nadie tiene que decidirlo a mano. Antes
    era `1.0.<run_number>`: el contador de ejecuciones de Actions, que subía con
    cada push a cualquier rama y no decía nada del cambio.
  - **Las builds de prueba llevan un cuarto número y no un sufijo**
    (`1.1.0.412`, no `1.1.0-dev.412`): `_parse_version` del autoupdate solo
    entiende números y leería el sufijo como `0`. Con el cuarto número, una
    build de prueba es más nueva que su release (no ofrece «volver» a ella) y
    más antigua que la siguiente (sí ofrece actualizar cuando sale).
  - **El bundle lleva `base` y el contador como build number** porque
    Flutter/macOS solo admiten tres números en la versión de la app.
  - **La última release se toma del tag más alto**, no de un fichero de la
    rama: así acierta en `develop` y en las `feature/**` aunque no se haya
    fusionado `main` de vuelta tras una release.
  - **`Release-As` tiene que ser mayor que la última release**; si no, el job
    `version` falla y no se publica nada: los ordenadores que ya la tienen no
    verían la nueva como más reciente y no se actualizarían. Para usarlo, un
    commit vacío en la rama que vaya a `main`:
    `git commit --allow-empty -m "chore(release): publica la 2.0.0" -m "Release-As: 2.0.0"`.
  - **No se usa release-please** (se probó en la rama `feature/versionado-semver`): saca cada
    versión con dos PRs (la normal a `main` y una PR de release automática) y
    necesita que la organización deje a GitHub Actions crear PRs, que está
    desactivado en `its-irb`. Aquí `main` ya es la rama de releases: a ella
    solo llega `develop` cuando se quiere publicar.

  La plantilla (`version = "0.0.0"`) y el `version.py` del repositorio
  (`0.0.0.dev`, la versión de desarrollo, que no busca actualizaciones) se
  sobrescriben siempre. Los tests del script están en
  `tests/unit/ci/test_next_version.py` (ver [testing.md](testing.md)).
- **Job `build-macos`** (matriz por app, runner `macos-26`, Apple
  Silicon; fijado en vez de `macos-latest` para que una imagen nueva de macOS
  no cambie el build sin que lo decidamos): descarga assets (mount: `macos-assets-downloader.sh`;
  transfer: `macos-rclone-downloader.sh`, con `RCLONE_ARCH=arm64` para
  determinismo), `uv sync`, `flet build macos --output dist --no-rich-output`
  (con `echo "y" |` para autoconfirmar); en mount copia `fuse_t.framework` al
  bundle; genera un **DMG** (action `create-dmg`) → artefacto
  `bifrost-<flavour>-macos.dmg`.
- **Job `build-macos-intel`** (matriz por app, runner `macos-15-intel`): copia
  del job anterior usando los mismos scripts de descarga con
  `RCLONE_ARCH=amd64` → artefacto `bifrost-<flavour>-macos-intel.dmg`. Los Macs
  Intel están soportados. Antes usaba `macos-14`, que GitHub Actions ya no
  admite, con `continue-on-error`; ahora no lo lleva, así que si el build de
  Intel falla, la release no se publica.
- **Job `build-windows`** (matriz por app): descarga rclone, `uv sync`,
  `uv run flet build windows --output dist --no-rich-output -v`,
  **Inno Setup** (`ISCC.exe` sobre `installer.iss` con
  `/DBranchSuffix`, `/DAppVersion=<version>` (con cuatro números en las builds
  de prueba), `/DAppName=<app>`) →
  `installer/*.exe`, y **firma el instalador** con `signtool` (certificado
  PFX desde los secrets del repo `IRBCODESIGNING` /
  `IRBCODESIGNING_PASSWORD`, con timestamp de Digicert). Comprime el
  instalador firmado en `bifrost-<flavour>-<rama>-windows.zip` (para la
  descarga manual: los navegadores avisan al bajar un `.exe` pero no un `.zip`)
  y sube el `.exe` y ese `.zip` como artefacto `<app>-windows`.
- **Job `release`** (solo en `main` y solo si el job `version` devuelve
  `is_release=true`): descarga los artefactos de los tres jobs de build (por eso
  su `needs` incluye también `build-macos-intel`) y publica la release de GitHub
  «Release vX.Y.Z» con tag `vX.Y.Z` sobre el commit compilado
  (`target_commitish`) y, como notas, los commits que sacan versión agrupados en
  cambios incompatibles, nuevas funciones, arreglos y otros
  (`next_version.py notes`). Contiene:
  - macOS: `bifrost-<flavour>-macos.dmg` (Apple Silicon) y
    `bifrost-<flavour>-macos-intel.dmg` (Intel)
  - Windows, tres ficheros a propósito: `bifrost-<flavour>-<rama>-windows.exe`
    (instalador firmado), `bifrost-<flavour>-<rama>-windows.zip` (el `.zip` del
    job `build-windows`) y `bifrost-<flavour>-windows.zip` (el mismo instalador
    comprimido; lo crea el propio job `release` con `zip`). El `.zip` es el que descargan los usuarios
    y el autoupdate, que extrae el `.exe` de dentro
    (`extract_windows_installer()`). El `.exe` suelto se mantiene porque las
    versiones anteriores lo siguen pidiendo (`-main-windows.exe`)

  De estas releases descarga el autoupdate de las apps
  (`backend.download_new_binary()`): en macOS elige el sufijo según la
  arquitectura de la máquina (`platform.machine()`: arm64 → `-macos.dmg`,
  x86_64 → `-macos-intel.dmg`) y en Windows descarga `-windows.zip`; solo los
  Macs Intel con una release anterior a los builds de Intel necesitan una
  instalación manual del `-macos-intel.dmg`.

## Política de validación

Los tests automáticos (pytest) cubren solo una parte del autoupdate, qué cubren y qué no, cómo
ejecutarlos y la prueba manual del autoupdate están en [testing.md](testing.md).
Todo lo demás se valida ejecutando las apps manualmente (`flet run`, y en su caso
`flet run --web`). Las funciones críticas a probar manualmente tras un cambio:

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
