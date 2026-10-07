# PLAN — BIFROST: stopgap macOS Intel (`.dmg` x86_64) hasta nov-2026

> **Rama:** continuar en `feature/rclone-arm64-macos` (contiene el fix arm64 `8d97751` y
> los renames de scripts aún sin commitear). Opcional: renombrar a
> `feature/macos-rclone-arch` por coherencia de scope.
>
> **Decisión del equipo (2026-10):** mantener el `.dmg` arm64 (código nuevo) **y**
> restaurar la "versión antigua" para Macs Intel como **stopgap hasta el 2-nov-2026**,
> fecha en la que GitHub retira por completo el runner `macos-14` (el último Intel
> hosted; deprecation iniciada el 6-jul-2026, issue runner-images #13518).
>
> **Diseño:** scripts separados por arquitectura (decisión del equipo):
> - `*-arm.sh` → job ARM (código nuevo, arch-aware)
> - `*-intel.sh` → job Intel (código antiguo tal cual, hardcodeado a `osx-amd64`)

---

## 1. Estado actual (verificado 2026-10-07)

### 1.1 Scripts en `shared/` (hechos, por verificar/commitear)

| Fichero | Contenido | Estado |
|---|---|---|
| `macos-assets-downloader-arm.sh` | Código nuevo arch-aware (`RCLONE_ARCH` override + `uname -m`; rclone + fuse-t 1.0.49 + fuente) | ✓ verificado (rename de `macos-assets-downloader.sh` tras `8d97751`) |
| `macos-rclone-downloader-arm.sh` | Código nuevo arch-aware (rclone + fuente) | ✓ verificado (rename de `macos-rclone-downloader.sh`) |
| `macos-assets-downloader-intel.sh` | **Código antiguo tal cual** (hardcodeado `osx-amd64`; rclone + fuse-t + fuente) | ✓ verificado, idéntico al pre-`8d97751` |
| `macos-rclone-downloader-intel.sh` | **Código antiguo tal cual** (hardcodeado `osx-amd64`; rclone + fuente) | ✓ verificado, idéntico al pre-`8d97751` |

- `git status`: los 2 ficheros antiguos en estado `D` (borrados), los 4 nuevos `??`
  (untracked) → **todo pendiente de commitear**.
- Nota: `macos-rclone-downloader-arm.sh` no termina en salto de línea (cosmético;
  añadir opcional).
- Nota: los `-arm.sh` siguen siendo **auto-detect** (en una máquina Intel bajarían
  `amd64`). El sufijo `-arm` identifica el job, no fuerza la arquitectura. Para
  determinismo total, el job ARM puede fijar `RCLONE_ARCH=arm64` (§3.2a, opcional).

### 1.2 Referencias al NOMBRE ANTIGUO que quedarían rotas (CRÍTICO)

Con los scripts antiguos borrados, estas referencias apuntan a ficheros inexistentes.
**Si se hace push sin actualizarlas, la CI falla** (`bash: ...: No such file or
directory`) y el build local (`build-macos.sh`) también:

| Fichero | Líneas | Uso |
|---|---|---|
| `.github/workflows/main.yml` | 95, 97 | Job `build-macos` (CI ARM) |
| `bifrost-mount/build-macos.sh` | 19, 20 | Build local (mount) |
| `bifrost-transfer/build-macos.sh` | 19 | Build local (transfer) |
| `README.md` | 70-71, 150, 162 | Docs (estructura + "Primera vez") |
| `docs/development/build-and-ci.md` | 69, 76, 98, 214 | Docs devs |
| `docs/development/backend.md` | 17-18, 125-126 | Docs devs (tabla de scripts) |
| `docs/agent/operations.md` | 36, 37 | Docs agentes |

(`docs/superpowers/plans/PLAN-rclone-arm64.md` cita los nombres antiguos pero es el
registro histórico del PR arm64 → **no se toca**.)

## 2. Objetivo y resultado esperado

- Cada release macOS publica **2 `.dmg` por app**:
  - `bifrost-<app>-macos.dmg` → **arm64** (job actual, runner `macos-latest`, script `-arm.sh`)
  - `bifrost-<app>-macos-intel.dmg` → **x86_64** ("versión antigua"; runner `macos-14`, script `-intel.sh`)
- Windows y el resto del pipeline: sin cambios.
- **Autoupdate: sin cambios de código.** `get_update_file_suffix()` (backend.py:260-269)
  sigue devolviendo `-macos.dmg` → objetivo del autoupdate = la build **arm64**.
  Usuarios Intel: descarga **manual** de `-macos-intel.dmg` desde la página de release.
- Tras el 2-nov-2026: el job Intel fallará (runner retirado) pero **no bloqueará la
  release** (`continue-on-error`); se elimina por completo en el follow-up §7.

## 3. Cambios detallados

### 3.1 Scripts `shared/` — SIN CAMBIOS (ya están)

Solo commitear el estado actual (renames + 2 nuevos `-intel.sh`). No editar el
contenido.

### 3.2 `.github/workflows/main.yml`

**(a) Job `build-macos` (ARM)** — actualizar referencias de scripts (main.yml:92-98):

```yaml
      - name: Descargar rclone y fuse-t para macOS
        run: |
          if [ "${{ matrix.app }}" = "bifrost-mount" ]; then
            cd ${{ matrix.app }}/src && bash ../../shared/macos-assets-downloader-arm.sh
          else
            cd ${{ matrix.app }}/src && bash ../../shared/macos-rclone-downloader-arm.sh
          fi
```

Opcional (determinismo): añadir `env: RCLONE_ARCH: arm64` al paso, de modo que aunque
GitHub cambiara la arquitectura de `macos-latest` en el futuro, el job ARM seguiría
bajando arm64.

**(b) Nuevo job `build-macos-intel`** — copia completa del job `build-macos`
(main.yml:54-147) con estas diferencias (el resto de steps — checkout, setup-python
3.12, versión, pyproject, uv sync, build, fuse_t al bundle, dmg, artefacto — idénticos):

```yaml
  build-macos-intel:
    runs-on: macos-14
    # Tras el 2-nov-2026 (macos-14 retirado) este job fallará: no debe bloquear
    # la release. Eliminar el job por completo en el follow-up (§7).
    continue-on-error: true
    strategy:
      matrix:
        app: [bifrost-transfer, bifrost-mount]
    steps:
      # ... steps idénticos a build-macos, salvo: ...

      - name: Descargar rclone y fuse-t para macOS (Intel)
        run: |
          if [ "${{ matrix.app }}" = "bifrost-mount" ]; then
            cd ${{ matrix.app }}/src && bash ../../shared/macos-assets-downloader-intel.sh
          else
            cd ${{ matrix.app }}/src && bash ../../shared/macos-rclone-downloader-intel.sh
          fi

      # ... y al final: ...

      - name: Crear DMG
        uses: L-Super/create-dmg-actions@v1.0.3
        with:
          dmg_name: ${{ matrix.app }}-macos-intel
          src_dir: ${{ matrix.app }}/dist/${{ matrix.app }}.app

      - name: Subir artefacto
        uses: actions/upload-artifact@v7.0.0
        with:
          name: ${{ matrix.app }}-macos-intel
          path: "*.dmg"
```

Notas:
- En `macos-14` todo es nativo x86_64: Python 3.12 de `setup-python` (image cachea
  3.12.10), wheels x86_64 de `uv sync`, shell Flutter x86_64 de `flet build macos`
  (sin `--arch`), rclone amd64 del script `-intel.sh`, `fuse_t.framework` universal.
  → `.dmg` Intel homogéneo, sin cross-compile.
- El step "Añadir fuse_t.framework al bundle" (solo mount) se incluye igual
  (el framework es universal).

**(c) Job `release`** — main.yml:285:

```yaml
    needs: [build-macos, build-windows, build-macos-intel]
```

- **`needs`** garantiza que el artefacto Intel existe cuando la release hace
  `download-artifact` (sin `needs` habría carrera: el `.dmg` Intel podría no entrar
  en la release).
- **`continue-on-error`** (en el job Intel) hace que, tras nov-2026, su fallo no
  impida la release: `download-artifact` baja todo lo que exista y `files: dist/*`
  publica lo descargado. No hay que tocar el resto del job `release`.

### 3.3 Builds locales (`build-macos.sh`)

Los builds locales corren en el Mac del dev (Intel o ARM) → usan el script
**auto-detect** (`-arm.sh`), no el `-intel.sh`:

- `bifrost-mount/build-macos.sh:19-20`:
  ```bash
  bash ../../shared/macos-rclone-downloader-arm.sh
  bash ../../shared/macos-assets-downloader-arm.sh
  ```
- `bifrost-transfer/build-macos.sh:19`:
  ```bash
  bash ../../shared/macos-rclone-downloader-arm.sh
  ```

### 3.4 Docs (mismo PR)

- **`README.md`** (:70-71 estructura, :150 y :162 comandos "Primera vez"):
  nombres nuevos + nota stopgap: *"macOS: las releases incluyen
  `bifrost-<app>-macos.dmg` (Apple Silicon) y `bifrost-<app>-macos-intel.dmg`
  (Intel, stopgap hasta nov-2026 — descarga manual; el autoupdate usa el arm64)."*
- **`docs/development/build-and-ci.md`** (:69, :76, :98, :214): nombres nuevos +
  sección breve del job Intel (runner `macos-14`, `continue-on-error`, fecha límite
  2-nov-2026, follow-up de eliminación).
- **`docs/development/backend.md`** (:17-18 árbol, :125-126 tabla): 4 scripts con su
  propósito (`-arm` auto-detect para job ARM/dev local; `-intel` hardcodeado amd64
  para el job Intel de CI).
- **`docs/agent/operations.md`** (:36-37): nombres nuevos.
- **Wiki externa** ("Build, CI y releases"): misma nota, a mano (vive fuera del repo).
- `docs/superpowers/plans/PLAN-rclone-arm64.md`: **no tocar** (registro histórico).

## 4. Sin cambios (explícito)

- `shared/bifrost_backend/backend.py` — `get_update_file_suffix()` /
  `download_new_binary()`: el autoupdate sigue pidiendo `-macos.dmg` (arm64).
- `shared/bifrost_frontend/frontend.py` — flujo de instalación (`hdiutil`+`ditto`,
  frontend.py:339-381): agnóstico a la arquitectura; el `.app` dentro de ambos `.dmg`
  se llama `bifrost-<app>.app`.
- Job Windows, job `summary`, triggers, versionado: intactos.

## 5. Riesgos y notas

1. **La rama está ahora rota** (scripts antiguos borrados, referencias sin actualizar)
   → todos los cambios de §3 van en el **mismo push**; no hacer push intermedio
   parcial que falle CI.
2. **Ventana de macos-14**: operativo con warnings hasta el 2-nov-2026. El stopgap
   expira exactamente ahí — por diseño.
3. **Toolchain en macos-14** (Xcode 15.0-16.2) con flet 0.84/Flutter: funcionaba
   cuando el yml estaba fijado a `macos-14` (commit `a8798c5`); el push de la rama lo
   valida en CI antes de mergear.
4. **Post-nov-2026**: job Intel en rojo (no bloqueante) hasta que se elimine (§7).
5. **Fallo parcial de la matriz Intel**: si un app falla y el otro sube su artefacto,
   la release incluye solo uno de los dos `.dmg` Intel (visible en el run; acceptable
   en stopgap).
6. **Riesgo preexistente y aceptado**: apps instaladas de la era Intel (releases
   antiguas) piden siempre `-macos.dmg` fijo → se autoupdatearían a arm64 y dejarían
   de arrancar en su Mac Intel. No es arreglable desde la CI (binarios viejos con
   nombre fijo); queda documentado.
7. **Naming `-arm.sh`**: identifica el job, no fuerza arch (el script sigue siendo
   auto-detect). Opcional: `RCLONE_ARCH=arm64` en el job ARM.

## 6. Verificación (sin suite de tests)

1. **Sintaxis** local: `bash -n shared/macos-*-downloader-*.sh` (4 ficheros).
2. **Push de la rama** (CI dispara en `feature/**`) → deben correr 4 builds macOS
   (2 en `macos-latest`, 2 en `macos-14`) + Windows. Sin fallos.
3. **Artefactos**: 4 `.dmg` (`-macos`, `-macos-intel` × 2 apps) + 2 `.exe`.
4. **Coherencia de arquitectura por `.dmg`** (los 4):
   ```bash
   hdiutil attach bifrost-mount-macos.dmg -nobrowse
   file "/Volumes/bifrost-mount-macos/bifrost-mount.app/Contents/MacOS/bifrost-mount"  # → arm64
   find "/Volumes/bifrost-mount-macos" -name rclone -type f -exec file {} \;           # → arm64
   find "/Volumes/bifrost-mount-macos" -name "python3.12" -type f -exec file {} \;    # → arm64
   hdiutil detach "/Volumes/bifrost-mount-macos"
   # repetir con bifrost-mount-macos-intel.dmg (y los de transfer) → todo x86_64
   ```
5. **Mac Intel real** (best effort, si el equipo tiene uno): montar
   `bifrost-mount-macos-intel.dmg` → arrancar → login → STS → app usable.
6. **Simular post-nov-2026** (opcional, en push de prueba): apuntar temporalmente
   `runs-on:` del job Intel a un runner inexistente → el job falla → verificar que el
   resto del pipeline (incl. release en `main`/`release`) se completa sin él.
7. **Release real** (tras merge a `main`/`release`): 4 `.dmg` + 2 `.exe` en la
   release de GitHub.

## 7. Follow-up (con fecha)

- **Issue/Jira (crear al mergear):** *"Eliminar `build-macos-intel` + su entrada en
  `needs` de release + notas de stopgap en docs — tras el 2-nov-2026"*.
- Con `continue-on-error`, el olvido no rompe la release (job rojo no bloqueante),
  pero el follow-up sigue siendo necesario para limpieza.

## 8. Commits propuestos (convención del repo, ver historial)

1. `ci(macos): separa downloaders por arquitectura (-arm/-intel) y renombra`
   → los 4 scripts de `shared/` (renames + 2 nuevos).
2. `ci(macos): añade build Intel (macos-14) con .dmg -intel [stopgap hasta nov-2026]`
   → `main.yml` (job ARM con `-arm.sh`, job `build-macos-intel`, `needs` de release).
3. `fix(build): build-macos.sh usa downloaders -arm`
   → `bifrost-mount/build-macos.sh` + `bifrost-transfer/build-macos.sh`.
4. `docs: downloaders por arquitectura y stopgap Intel en docs`
   → `README.md`, `docs/development/*`, `docs/agent/operations.md`.

(Alternativa: un único commit `ci(macos): ...` si el equipo prefiere PR mono-commit.)

## 9. Definition of done

- [ ] Los 4 scripts de `shared/` commiteados (2 renames + 2 `-intel.sh`)
- [ ] `main.yml`: job ARM con `-arm.sh`; job `build-macos-intel`
      (`macos-14` + `continue-on-error` + naming `-intel`); release `needs` actualizado
- [ ] `build-macos.sh` (×2) con `-arm.sh`
- [ ] Docs actualizadas (README + docs/development + docs/agent) con nota de stopgap
- [ ] CI en la rama: 4 `.dmg` + 2 `.exe`; chequeo de arquitectura por `.dmg` OK (§6.4)
- [ ] `.dmg` Intel arrancando en Mac Intel real (o pendiente registrado)
- [ ] Issue de follow-up (2-nov-2026) creado
- [ ] Push a origin (CI builda)
