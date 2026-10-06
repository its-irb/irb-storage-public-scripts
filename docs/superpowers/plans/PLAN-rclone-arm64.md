# PLAN — BIFROST: rclone por arquitectura en macOS (Apple Silicon)

> **Rama:** `feature/rclone-arm64-macos` (crear desde `develop`)
>
> El nombre empieza por `feature/` porque la CI (`.github/workflows/main.yml:11-14`) solo
> builda `main`, `release`, `develop` y `feature/**`.
>
> **Estado del código:** este plan se escribe ANTES de tocar nada. Cuando se ejecute,
> verificar que las líneas citadas siguen siendo las mismas.
>
> **Alcance:** solo **arm64** (dev + CI). El soporte Intel (`.dmg` x86_64 para Macs
> Intel + autoupdate por arquitectura) es un plan separado:
> `PLAN-rclone-intel-macos.md` (Vía A: cross-compile en runner ARM, con fallback
> Vía B: runner self-hosted Intel). Este PR deja la CI y el nombre del `.dmg`
> (`<app>-macos.dmg`) tal y como están hoy.

---

## 1. Contexto

- En un Mac **Apple Silicon sin Rosetta 2**, las apps fallan en la primera invocación de
  rclone (renovación STS, `main.py:476` → `configure_rclone` → `obtener_ruta_rclone_conf`,
  `backend.py:311`) con:

  ```
  OSError: [Errno 86] Bad CPU type in executable:
  '.../bifrost-mount/src/assets/bin/rclone'
  ```

- El flujo de instalación seguido (doc "Build, CI y releases": `cp` plantilla + `sed` +
  `uv sync` + scripts de assets desde cada `src/`) era el correcto. **El bug es de los
  scripts de descarga, no de la instalación.**

## 2. Causa raíz (verificada)

- `uname -m` del Mac dev → `arm64`. Sin Rosetta (`/Library/Apple/usr/bin/arch` no existe).
- `file bifrost-mount/src/assets/bin/rclone` → `Mach-O 64-bit executable x86_64`
  (igual en `bifrost-transfer/`).
- Los dos scripts macos **hardcodean la build Intel**:
   - `shared/macos-assets-downloader.sh:6` (mount, URL) y `:26` (`cp` del binario).
   - `shared/macos-rclone-downloader.sh:5` (transfer, URL) y `:19` (`cp` del binario).
- **No hay detección de arquitectura en ningún sitio** del pipeline: grep de
  `uname`/`arm64`/`ARCH` en `shared/*.sh` + `bifrost-{mount,transfer}/build-macos.sh`
  → 0 coincidencias.
- Huella histórica: commit `c68ef79` *"añadir amd64 en otro sitio (soy tonta"* — la URL
  amd64 ya se parcheó a mano en su día (script escrito en Mac Intel, donde era nativo).
- La toolchain **sí** detecta la arquitectura al compilar (Xcode/Flutter → el `.app` sale
  arm64 en runner arm64), pero rclone no se compila: se descarga con `curl` de una URL
  fija → nadie elige la arquitectura.
- `fuse_t.framework` es **universal** (x86_64+arm64, verificado con `lipo -archs`) →
  fuera de scope de este bug.
- Windows (`windows-amd64`) y Linux (`linux-amd64`) usan la arquitectura nativa de su
  target → no afectados.

### ¿Por qué solo en macOS? (versión simple)

1. **Un binario solo habla el idioma de una CPU.** Hay dos "idiomas" principales:
   **Intel (x86_64)** y **ARM (arm64)**. Un binario para Intel no corre nativo en una
   CPU ARM, y viceversa.
2. **Windows y Linux: el target nunca cambió de arquitectura.** PCs Windows = Intel
   (x86_64) desde hace ~15 años; clúster IRB = servidores Intel. El script pide la
   edición Intel y el equipo es Intel → coincide siempre.
3. **Mac: el target SÍ cambió, y el script no.** Hasta 2020 todos los Mac eran Intel —
   el script se escribió entonces ("Mac = Intel, descargo la edición Intel"). Desde
   2020 los Mac nuevos usan chips de Apple (M1–M4) que son **ARM** (la familia del
   móvil). El script nadie lo tocó: sigue pidiendo la edición Intel. Mac Intel viejo →
   bien; **Mac ARM (como el del dev) → edición en un idioma que su CPU no habla** →
   `Bad CPU type in executable`.
4. **Por qué "funciona" en algunos Mac y no en otros.** Un Mac ARM puede instalar un
   traductor, **Rosetta 2**, que lee programas Intel en su nombre — pero **no viene por
   defecto**. Los Mac donde la app "funcionaba" lo tenían instalado → el rclone Intel
   corría emulado sin que nadie notara nada. Mac sin Rosetta → boom. (En Windows on ARM
   la emulación x86_64 viene de serie, así que ni se manifestaría ahí.)
5. **Por qué la app arranca y rclone no.** La app se **compila en la propia CI** (runner
   arm64) → sale en el idioma correcto (ARM). Rclone **no se compila**: se descarga de
   Internet una edición ya hecha, desde una URL escrita a mano → siempre la edición
   Intel.

En una frase: *en Windows/Linux el "idioma" del equipo nunca cambió y el script pedía el
correcto; en Mac el equipo cambió de idioma (Intel→ARM) y el script sigue pidiendo el de
siempre — y como el traductor (Rosetta) no viene por defecto, los Mac nuevos sin él se
parten.*

## 3. Impacto en usuarios (la pregunta que motivó esto)

> **IMPORTANTE: este bug no es solo de dev — los usuarios que descargan el `.dmg`
> "de forma normal" tienen el MISMO problema.** El `.dmg` no se construye a mano:
> la CI ejecuta **exactamente los mismos scripts** `.sh` que el dev local
> (`main.yml:95-97`):
>
> ```yaml
> cd ${{ matrix.app }}/src && bash ../../shared/macos-assets-downloader.sh   # mount
> cd ${{ matrix.app }}/src && bash ../../shared/macos-rclone-downloader.sh   # transfer
> ```
>
> → el runner (arm64) descarga el rclone **Intel** → lo empaqueta dentro del `.dmg` →
> **todo `.dmg` publicado lleva rclone x86_64 dentro.** Dev y producción comparten el
> mismo pipeline de descarga, así que ambos salen con la arquitectura equivocada.

Evidencia: CI `main.yml:55` `runs-on: macos-latest`, que hoy es ARM (la imagen
`macos-14` empezó en runners Intel y pasó a ARM en 2024; `macos-13` fue la última
exclusivamente Intel) → **todos los `.dmg` recientes son app arm64 + rclone x86_64**.

| Quién | Cómo obtiene rclone | Arquitectura | ¿Problema? |
|---|---|---|---|
| Dev (este Mac) | Scripts `.sh` locales | Intel | Sí — `EBADCPU` (lo que motivó el bug) |
| Usuario M-series **con** Rosetta 2 | `.dmg` de la release (CI) | Intel (emulado) | No — por eso no se ha detectado |
| Usuario M-series **sin** Rosetta | `.dmg` de la release (CI) | Intel | **Sí — el mismo `EBADCPU` en producción** (un Mac M1–M4 nuevo suele no traer Rosetta) |
| Usuario Intel | `.dmg` de la release (CI) | — | El `.app` es arm64-only (build en runner arm64) → **no arranca** (se soluciona en `PLAN-rclone-intel-macos.md`, fuera de este PR) |

Windows / Linux: no afectados.

**Conclusión:** el fix (detectar `uname -m` en los scripts) arregla los dos frentes a la
vez — el dev local y el próximo `.dmg` de CI — porque ambos pasan por el mismo código.

## 4. Diseño

- **Detección de arquitectura en los 2 scripts macos** con `uname -m`, con override
  opcional por env-var (lo necesitará el build cross-Intel de
  `PLAN-rclone-intel-macos.md`: en un runner ARM construyendo para Intel, `uname -m`
  diría `arm64` y haría falta forzar `amd64`):

  ```bash
  case "${RCLONE_ARCH:-}" in
    arm64|amd64) ;;
    *) case "$(uname -m)" in
         arm64) RCLONE_ARCH=arm64 ;;
         *)     RCLONE_ARCH=amd64 ;;
       esac ;;
  esac
  ```

  - La versión one-liner (`RCLONE_ARCH="${RCLONE_ARCH:-$(case ... esac)}"`) es
    **bash inválido**: el `)` del patrón `in arm64)` cierra la sustitución de
    comando dentro de las comillas (verificado al ejecutar). Se usa el bloque
    multi-línea.
  - Sin override, fallback `*` → `amd64`: comportamiento actual en Intel y en
    cualquier caso extraño. Un valor de override no reconocido (`RCLONE_ARCH=weird`)
    cae a la detección nativa.
  - rclone publica builds por arquitectura (`osx-arm64` existe desde v1.59; usamos
    1.72.1 → disponible). No hay build universal para macOS → lo correcto es la build
    nativa por arquitectura (recomendación de rclone).
- **CI queda arreglada sola**: el runner arm64 (`macos-latest`) descargará arm64 → el
  `.dmg` contendrá rclone nativo → usuarios M-series sin Rosetta funcionan.
- No se tocan los scripts de Windows/Linux ni los `build-macos.sh` (llaman a los
  downloaders; no eligen arquitectura). Nota: `bifrost-mount/build-macos.sh` llama a
  los **dos** downloaders en la build local; ambos quedan corregidos con este PR.
- Los binarios descargados están gitignored (`.gitignore:29-33`) → **lo único que se
  commitea son los 2 scripts**.

## 5. Cambios detallados

### 5.1 `shared/macos-assets-downloader.sh` (bifrost-mount)

```bash
# ANTES (:5-6)
RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-amd64.zip"

# DESPUÉS
RCLONE_VERSION="1.72.1"
case "${RCLONE_ARCH:-}" in
  arm64|amd64) ;;
  *) case "$(uname -m)" in
       arm64) RCLONE_ARCH=arm64 ;;
       *)     RCLONE_ARCH=amd64 ;;
     esac ;;
esac
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-${RCLONE_ARCH}.zip"
```

(También se actualizan a `${RCLONE_ARCH}` el nombre local del zip en el `curl -o`
y el `unzip`, que tenían `osx-amd64` fijo — solo cosmético, es un nombre temporal.)

```bash
# ANTES (:26)
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-amd64/rclone" ./assets/bin/rclone

# DESPUÉS
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-${RCLONE_ARCH}/rclone" ./assets/bin/rclone
```

### 5.2 `shared/macos-rclone-downloader.sh` (bifrost-transfer)

Mismo patrón en las 2 líneas:

```bash
# ANTES (:5)
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-amd64.zip"

# DESPUÉS: mismo bloque de detección + RCLONE_URL con ${RCLONE_ARCH}
```

```bash
# ANTES (:19)
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-amd64/rclone" ./assets/bin/rclone

# DESPUÉS
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-${RCLONE_ARCH}/rclone" ./assets/bin/rclone
```

(En `macos-rclone-downloader.sh` la línea `RCLONE_ARCH=...` se añade tras
`RCLONE_VERSION="1.72.1"` de la `:4`, igual que en el otro script.)

### 5.3 Docs (mismo PR, 1 commit)

- `README.md` y `CLAUDE.md` (sección de assets): nota breve — "los scripts macos
  descargan rclone según la arquitectura de la máquina (`arm64` en Apple Silicon,
  `amd64` en Intel); no hace falta Rosetta".
- La wiki externa ("Build, CI y releases", §"Primera vez") vive fuera de este repo →
  actualizarla a mano cuando se pueda (mismo texto).

## 6. Desarrollo local (desbloquear el Mac dev)

Tras aplicar §5, regenerar los binarios locales (gitignored) re-ejecutando los scripts
corregidos, **desde la `src/` de cada app**:

```bash
cd bifrost-mount/src && bash ../../shared/macos-assets-downloader.sh
cd bifrost-transfer/src && bash ../../shared/macos-rclone-downloader.sh
```

Verificación inmediata:

```bash
file bifrost-mount/src/assets/bin/rclone          # → Mach-O 64-bit executable arm64
file bifrost-transfer/src/assets/bin/rclone       # → Mach-O 64-bit executable arm64
bifrost-mount/src/assets/bin/rclone version       # → rclone v1.72.1 (sin EBADCPU)
```

Alternativa de desbloqueo inmediato (sin esperar al fix, mismo resultado):

```bash
cd /tmp && curl -L -s https://downloads.rclone.org/v1.72.1/rclone-v1.72.1-osx-arm64.zip -o rclone-arm64.zip && unzip -o rclone-arm64.zip
cp rclone-v1.72.1-osx-arm64/rclone bifrost-mount/src/assets/bin/rclone
cp rclone-v1.72.1-osx-arm64/rclone bifrost-transfer/src/assets/bin/rclone
```

## 7. Verificación (sin suite de tests en el repo)

### 7.1 Local (requiere VPN)

```bash
cd bifrost-mount && source .venv/bin/activate && flet run
```

- Login → renovación STS **completa sin `EBADCPU`** ("Writing to rclone config..." →
  continúa) → app usable.
- **Ojo:** el botón Mount seguirá fallando en dev por el bug de la ruta de
  `fuse_t.framework` (el código busca `src/frameworks/` y el script descarga a
  `frameworks/`, y con el wheel instalado las rutas `__file__`-relativas resuelven a
  `site-packages/`). Es otro bug (ver "Fuera de scope", §8) — no tomarlo como regresión.

### 7.2 CI (el chequeo que importa para usuarios)

1. Push de la rama → la CI builda los 2 `.dmg` (job `build-macos`, runner arm64).
2. Descargar el artefacto `bifrost-mount-macos.dmg`:

   ```bash
   hdiutil attach bifrost-mount-macos.dmg
   find /Volumes/* -name rclone -type f
   file "$(find /Volumes/* -name rclone -type f | head -1)"   # → debe decir arm64
   hdiutil detach /Volumes/*
   ```

   (mismo para `bifrost-transfer-macos.dmg`)

### 7.3 Intel (best effort)

- No hay Mac Intel disponible para probar; el fallback `*` → `amd64` preserva el
  comportamiento actual. Si algún día hay uno: el script debe seguir descargando amd64.

## 8. Riesgos, pendientes y fuera de scope

1. **Disponibilidad de la URL arm64**: `rclone-v1.72.1-osx-arm64.zip` existe (rclone
   publica arm64 desde v1.59). Antes de mergear, un `curl -I` a la URL descarta dudas.
2. **`.dmg` arm64-only vs Macs Intel (RESUELTO: plan separado):** el equipo ha
   confirmado que los Macs Intel **siguen siendo target**. El soporte Intel (`.dmg`
   x86_64 + autoupdate por arquitectura) se desarrolla en `PLAN-rclone-intel-macos.md`
   (Vía A: cross-compile en runner ARM; fallback Vía B: runner self-hosted Intel).
   Este PR deja la CI como está hoy (solo arm64) y el `.dmg` se sigue llamando
   `<app>-macos.dmg`.
3. **Fuera de scope (bugs conocidos, otro PR):**
   - Ruta dev de `fuse_t.framework` rota en `backend.py:548,826` (`src/frameworks` vs
     `frameworks`; `__file__`-relativas muertas con el wheel no editable) → el mount en
     dev no funciona.
   - Diálogo "FUSE / WinFSP not detected" genérico → `PLAN-logging-improvements.md`.
4. **Binarios locales**: tras mergear, cada dev debe re-ejecutar los downloaders (o el
   paso §6) para renovar su copia local; es el flujo "Primera vez" habitual.
5. **No se versiona nada nuevo**: solo los 2 scripts macos cambian en el repo.

## 9. Definition of done

Ejecución del 2026-10-06 (estado real):

- [x] Rama `feature/rclone-arm64-macos` creada desde `develop`
- [x] `macos-assets-downloader.sh` + `macos-rclone-downloader.sh` arch-aware
      (`arm64`/`amd64` según `uname -m`). El one-liner del §4 resultó ser bash
      inválido (ver nota en §4) → bloque `case` multi-línea.
- [x] Binarios locales del Mac dev regenerados y verificados (`file` → arm64,
      `rclone version` OK)
- [x] `curl -I` a la URL arm64 1.72.1 (sanity) → HTTP 200
- [x] Nota de arquitectura en `README.md` + `AGENTS.md` + `docs/agent/operations.md`.
      Desviación: `CLAUDE.md` es un stub ("Do not add content here") → la nota vive en
      `AGENTS.md`/`operations.md`; sin referencia a `PLAN-rclone-intel-macos.md` (aún
      sin commitear; se añadirá cuando exista).
- [x] Verificación parcial §7.1: la llamada de backend que fallaba
      (`obtener_ruta_rclone_conf` → `rclone config file`) ejecutada desde los venvs de
      ambas apps con `FLET_ASSETS_DIR` → OK, sin `EBADCPU`.
- [ ] `flet run`: login → STS se completa sin `EBADCPU` — **pendiente del usuario**:
      requiere VPN (Nexica) y credenciales. Al ejecutar el 2026-10-06 la VPN estaba
      desconectada.
- [ ] CI: los 2 artefactos `.dmg` contienen rclone **arm64** (chequeo §7.2) —
      **pendiente del push** (a petición del usuario, los commits quedaron sin hacer).
- [ ] Commits + push a origin (CI builda ambas apps) — **pendiente del usuario**
