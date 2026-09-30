# Operación: ejecución, empaquetado, CI y variables de entorno

## Desarrollo

**Prerrequisitos**: Python **≥ 3.11** (CI usa 3.12), **uv** (gestor de
entornos), VPN de Nexica (Forticlient) para **ejecutar** las apps (LDAP/MinIO).
`flet` (0.84.0) y el resto de deps van congeladas en el `pyproject.toml` de
cada app; las instala `uv sync`.

```bash
pip install uv
```

**Importante**: los binarios `rclone` y `fuse-t` **no están versionados**
(`src/assets/bin/` y `frameworks/` están gitignores, solo los `.keep`): hay
que descargarlos con los scripts `shared/*-assets-downloader.sh`.

Desde la carpeta de la app (`bifrost-mount/` o `bifrost-transfer/`):

```bash
# Primera vez: generar pyproject.toml desde la plantilla y apuntar __BUILDPATH__ a shared/
cp pyproject-template.toml pyproject.toml
sed -i '' "s|__BUILDPATH__|${PWD}/..|g" ./pyproject.toml   # macOS (sin '' en Linux)

# Entorno virtual
uv sync
```

Descarga de binarios (obligatorio; los scripts usan rutas relativas, así que
se ejecutan desde la `src/` de **cada app** — cada una descarga su propia
copia, aunque el comando sea el mismo; repetir el paso en la otra app):

```bash
cd src   # dentro de la app en la que estés (bifrost-mount/ o bifrost-transfer/)
# Solo el script de la plataforma correspondiente:
bash ../../shared/macos-assets-downloader.sh      # mount macOS: rclone + fuse_t.framework
bash ../../shared/macos-rclone-downloader.sh      # transfer macOS: rclone
bash ../../shared/windows-assets-downloader.sh    # Windows: rclone.exe
bash ../../shared/linux-assets-downloader.sh      # Linux (clúster): rclone
cd ..   # volver a la carpeta de la app
```

```bash
# Activar
source .venv/bin/activate            # macOS/Linux
# Windows: .\.venv\Scripts\Activate.ps1 (PowerShell) | .\.venv\Scripts\activate.bat (CMD)

# Ejecutar
flet run
```

Flags útiles:

```bash
flet run --customuser     # Login con usuario distinto al del sistema
flet run --update         # Forzar autoupdate
flet run --web            # (solo transfer) modo web para desarrollo local
BIFROST_CLUSTER=1 python src/main.py --web  # (solo transfer) simular producción OOD
```

Tras cambiar código de `shared/`, reinstalar el paquete compartido:

```bash
uv sync --reinstall-package bifrost-shared
```

## Empaquetado

Prerrequisito común: `pyproject.toml` local generado desde la plantilla con
`__BUILDPATH__` sustituido, venv sincronizado y assets descargados.

| Entorno | Notas |
|---|---|
| Windows local | Regenera `pyproject.toml`, descarga rclone, reinstala `bifrost-shared` y hace `flet build windows`. El instalador (Inno Setup) se empaqueta aparte. |
| macOS local | Desde la carpeta de la app; requiere Xcode. Versión local `2.0.0.dev`; en mount copia `fuse_t.framework` al bundle. |
| CI | `.github/workflows/main.yml` — macOS (`.app` → DMG) y Windows (build + Inno Setup + firma del instalador) para ambas apps. **No hay job de Linux.** |
| Linux (clúster) | Sin empaquetado: `bifrost-transfer` corre desde código en modo web (Open OnDemand, `BIFROST_CLUSTER=1`). |

Builds locales:

```bash
# macOS (desde la carpeta de la app)
./build-macos.sh
```

```powershell
# Windows (desde la raíz del repo)
.\build-windows.ps1 -app bifrost-mount    # o -app bifrost-transfer
```

Instalador Windows (Inno Setup, aparte del build):

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DAppVersion=<version> /DAppName=<app> /DBranchSuffix=<sufijo> <app>\installer.iss
```

Al añadir/actualizar dependencias Python (deps congeladas por app):

```bash
uv add <package>
```

## CI y releases

- Triggers: push a `main`, `release`, `develop`, `feature/**` (solo con
  cambios en las apps, `shared/` o el workflow) + `workflow_dispatch`.
- Toolchain CI: Python 3.12, `uv` vía pip, **Node 24** (necesario para
  `flet build windows`), `PYTHONUTF8=1` en Windows.
- La versión se inyecta como `1.0.<run_number>` en `src/version.py` y en el
  `pyproject.toml` de cada app antes del build (la versión de la plantilla es
  `2.0.0`).
- Job `release` (solo en `main` y `release`): publica la release con tag
  `v1.0.<run_number>` con los artefactos (macOS: `bifrost-<flavour>-macos.dmg`;
  Windows: instalador `.exe` **firmado** con `signtool`, PFX desde los
  secrets `IRBCODESIGNING`/`IRBCODESIGNING_PASSWORD`). El autoupdate de las
  apps descarga de esas releases.

## Tests

**No hay suite de tests automatizada.** Los cambios se validan ejecutando las
apps manualmente (`flet run`).

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal de producción OOD) |
| `BIFROST_NO_LDAP=1` | ambas | Salta la validación LDAP en el login (máquinas sin LDAP pero con acceso MinIO, p. ej. IVIS). El usuario igualmente introduce usuario+contraseña (necesarios para STS). Badge del header: `DESKTOP (NO LDAP)`. En Windows definirla como variable de sistema (ver abajo). |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar el `rclone` empaquetado |
| `FLET_APP_STORAGE_TEMP` | ambas | Setada por Flet; usada para debug de localización de binarios |

```powershell
# BIFROST_NO_LDAP como variable de sistema de Windows (aplica a todos los usuarios)
setx BIFROST_NO_LDAP 1 /M
```

## Higiene de commits

No commitear `.venv/`, `dist/`, `build/`, `src/version.py` generado, los
binarios descargados (`src/assets/**/*`, `frameworks/*`) ni los
`pyproject.toml` locales de las apps (solo las plantillas
`pyproject-template.toml`). Ver `.gitignore`.
