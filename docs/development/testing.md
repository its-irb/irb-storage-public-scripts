# Tests y validación

Punto de partida para probar BIFROST: qué hay automatizado, cómo ejecutarlo y cómo
comprobar a mano lo que los tests no pueden cubrir.

> **Esto no es una guía de pautas.** Aún no se han definido criterios de testing para el
> proyecto (qué se prueba, con qué herramientas, con qué estructura). Lo que hay aquí es lo
> que se hizo al empezar con el autoupdate, y está sujeto a cambios. Donde aparece una
> recomendación, es una sugerencia, no una norma acordada.

## Estado actual

- Hay **tests automáticos (pytest) solo de lógica pura**: el autoupdate
  (`shared/bifrost_backend/common/updates.py`), el análisis de la lista de procesos
  `rclone mount` (`shared/bifrost_backend/mount/processes.py`), el comando con el que se
  monta un servidor (`shared/bifrost_backend/mount/s3_mount.py`), dónde se busca rclone
  (`shared/bifrost_backend/common/rclone.py`) y, aparte, en `bifrost-transfer/tests/`, los
  perfiles y la validación de metadatos (`bifrost-transfer/src/meta_fields.py`).
- El resto del proyecto se valida **a mano**, ejecutando las apps (ver la política de
  validación en [build-and-ci.md](build-and-ci.md#política-de-validación)).
- Todavía **no** hay ruff, mypy ni tests en la CI: `pytest`, `ruff` y `mypy` no figuran
  en el `.github/workflows/main.yml` ni en ningún `pyproject.toml`.

## Tests automáticos

### Estructura

```text
pytest.ini                         # testpaths = tests
tests/
  conftest.py                      # hace importable shared/ y registra un `config` de pruebas
  unit/
    backend/
      test_updates.py              # lógica pura: versiones, sufijo por plataforma, should_check, .bat
      test_update_flow.py          # check de versión y descarga, con requests.get sustituido
      test_processes.py            # reconocer los `rclone mount` en la salida de ps / PowerShell
      test_s3_mount.py             # el comando de montaje: servidor entero, solo lectura y opciones
      test_rclone.py               # dónde se busca rclone: FLET_ASSETS_DIR, assets de la app, PATH

bifrost-transfer/tests/            # aparte: necesita el venv de transfer (importa flet y bifrost_frontend)
  conftest.py                      # añade bifrost-transfer/src al path
  test_meta_fields.py              # perfiles, provider, campos obligatorios, validación de tags, detect_profile
```

Decisiones tomadas hasta ahora (provisionales, se pueden cambiar cuando se defina una
estructura definitiva):

- Los tests están fuera de `shared/`, en `tests/`, organizados por tipo (`unit/`) y, dentro,
  reflejando `shared/`. Un fichero por módulo probado: `test_<módulo>.py`.
- Solo se crean las carpetas que tienen algo dentro.
- Los tests **no lanzan procesos reales**. Lo que toca la red se prueba
  sustituyendo `requests.get` con `monkeypatch` (ver `test_update_flow.py` y los límites en
  "Límites de sustituir `requests.get`").
- `conftest.py` añade `shared/` al path y registra un módulo `config` falso, porque `config`
  y `version` los aporta cada app (`bifrost-<flavour>/src/`), no `shared/`.

### Ejecutarlos

`pytest` no es todavía una dependencia del proyecto, así que se lanza con `uv` sin tocar
ningún entorno, desde la raíz del repo:

```powershell
uv run --no-project --python 3.12 --with pytest --with requests python -m pytest -q
```

Añade `-v` para ver cada test, o la ruta de un fichero para ejecutar solo ese.

Los de `bifrost-transfer/tests/` no entran en ese comando (`pytest.ini` solo mira `tests/`) y
necesitan el venv de transfer, porque `meta_fields.py` importa `flet` y `bifrost_frontend`. Desde
`bifrost-transfer/` (si ha cambiado `shared/`, reinstala antes `bifrost-shared`: `meta_fields.py`
importa componentes nuevos de `bifrost_frontend`):

```bash
uv sync --reinstall-package bifrost-shared
uv run --no-sync --with pytest python -m pytest tests -v
```

### Qué comprueban realmente

Los tests **no ejecutan el autoupdate**: comprueban que la lógica del código responde como
esperamos ante unas entradas que nosotros mismos fabricamos. Conviene tener claro qué
significa "pasa" en cada grupo:

- **Lógica pura** (`test_updates.py`): comparación de versiones (`2.10.0` es mayor que
  `2.0.0`, no se compara como texto), sufijo de descarga por plataforma y arquitectura
  (incluido Mac Intel) y cuándo se comprueba el update (`--update`, SLURM, ejecutables
  `_cluster`). Aquí el test sí valida el comportamiento real de la función.
- **Red simulada** (`test_update_flow.py`): `check_update_version` y `download_new_binary`
  frente a respuestas falsas de `requests.get`: versión nueva, igual o más antigua, error de
  la API, respuesta sin `tag_name`, sin red, descarga correcta y 404; y que se piden las URLs
  esperadas de GitHub. Valida cómo reacciona nuestro código a esas respuestas, **no** que
  GitHub responda así (ver "Límites de sustituir `requests.get`").
- **Extracción del `.zip`** (`test_updates.py`): `extract_windows_installer` saca el `.exe`
  de un `.zip` creado en el test, y falla si no hay ninguno o hay varios. No comprueba que el
  `.zip` real de la release tenga esa forma.
- **Texto del `.bat`** (`test_updates.py`): `build_windows_update_script` genera un texto que
  contiene `cd /d`, el instalador con `start /wait` y el relanzado, en ese orden. Es una
  comprobación **del contenido de un string**: no ejecuta el `.bat`, ni el instalador, ni
  demuestra que Windows se comporte como se espera. Protege contra que alguien borre o
  reordene esas líneas sin darse cuenta, nada más.
- **Procesos `rclone mount`** (`test_processes.py`): `parse_mount_processes` reconoce los
  `rclone mount` en la salida de `ps` (copiada de un macOS real, con el `go-nfsv4` de fuse-t, que
  lleva la carpeta en su línea de comandos y no es rclone) y en la de PowerShell, y deja fuera
  las copias; `pids_serving` distingue `…/bkt` de `…/bkt2`. La salida de PowerShell **no está
  capturada en Windows**: tiene la forma que esperamos de `Get-CimInstance`, así que el test
  valida nuestro análisis, no que Windows la devuelva así. También `server_mount_pids` (los
  rclone de un servidor entero: no `minio:bkt`, ni `minio-archive` para `minio`) y
  `drive_letter_in` (la letra de `rclone mount minio: X:`).
- **Comando de montaje** (`test_s3_mount.py`): `_mount_command` monta el servidor entero
  (`minio:`), en solo lectura y con las opciones de rendimiento en ese orden; `--allow-non-empty`
  solo fuera de Windows, y las opciones de caché que se pasan al arrancar la app van al final
  (rclone se queda con el último valor). No lanza rclone: no comprueba que rclone las acepte ni
  que el montaje vaya más rápido.
- **Dónde se busca rclone** (`test_rclone.py`): `app_assets_dir()` devuelve el `assets/` junto
  al `config.py` de la app (y None con el `config` de pruebas, que no tiene fichero);
  `get_rclone_executable()` encuentra el rclone de la app sin `FLET_ASSETS_DIR`, da prioridad a
  `FLET_ASSETS_DIR` y falla con `EnvironmentError` si no hay rclone en ningún sitio. Usa una app
  falsa en una carpeta temporal: no comprueba que exista el rclone real ni que funcione.
- **Metadatos** (`bifrost-transfer/tests/test_meta_fields.py`): campos de cada perfil con
  `provider` primero, `apply_provider`, campos obligatorios, límites y caracteres de los tags
  (`check_tag_value`, `validate_profile_tagset`) y `detect_profile`.

### Qué no cubren

- El reemplazo real del ejecutable y el relanzado, ni el `cwd` con el que `views/update.py`
  lanza el `.bat`: eso se comprueba con la prueba manual de abajo.
- El frontend (las vistas Flet) y el resto del backend.
- El proceso real de red (ver el apartado siguiente).

#### Límites de sustituir `requests.get`

`monkeypatch` evita usar la red, y por eso los tests son rápidos y no dependen de GitHub,
pero tiene un coste: la respuesta falsa la escribimos nosotros, a partir de lo que creemos
que devuelve GitHub. Por tanto **no se valida** el recorrido real por HTTPS:

- Que la API de GitHub siga devolviendo `tag_name` con el formato esperado (si cambiase, los
  tests seguirían en verde y la app fallaría).
- Que la URL de descarga de la release exista y redirija (302) al fichero real, ni que el
  `.exe` descargado sea el correcto o esté completo.
- Certificados TLS, proxies, timeouts y límites de peticiones de la API.

Si el fake y la realidad divergen, los tests pasan igualmente. Esa parte solo se comprueba con
la prueba manual contra la release real (más abajo).

### Comprobar que un test detecta el fallo (recomendación)

Que un test pase no demuestra que sepa detectar errores. Una forma de comprobarlo es
**romperlo a propósito** y ver que falla: por ejemplo, quita `start /wait` de
`build_windows_update_script()` y ejecuta los tests; debe fallar
`test_windows_script_waits_for_installer_before_relaunch`. Restaura el cambio y comprueba
que vuelve a pasar.

Si el test es para un **problema real que hay que arreglar**, se recomienda escribirlo
**antes** del arreglo: debe fallar (rojo) con el código actual y pasar (verde) después. Así
se comprueba que el test sabe detectar el problema.

### Añadir un test

Cómo se ha hecho hasta ahora, como referencia:

1. Crear `tests/unit/<área>/test_<módulo>.py` (o ampliar el existente).
2. Lo que toca red o ficheros reales se ha sustituido con `monkeypatch` por simplicidad (no
   es obligatorio, y tiene las limitaciones descritas arriba).
3. Ejecutar el test y romperlo a propósito para ver que falla.

## Prueba manual del autoupdate (Windows)

Pytest solo comprueba la lógica del updater (ver arriba). Lo que ocurre **después** de
descargar (instalar, relanzar) y todo el recorrido real por HTTPS solo se comprueban con el
binario empaquetado y una actualización real.

Tras pulsar *Update*, la app debe cerrarse, instalarse la versión nueva y **relanzarse sola
y abrir con normalidad**.

### Cómo probarlo: contra la última release real de GitHub

No requiere hacer commit ni montar ningún servidor: se compila el build con una versión
inferior a la última release y se deja que se actualice con la real.

1. Pon una versión baja en `bifrost-<flavour>/src/version.py` (p. ej. `0.0.1`), compila el
   build empaquetado e instálalo (ver "Compilar e instalar").
2. Abre la app instalada.
3. Pulsa *Update* y **no abras la app a mano**. Debe instalarse y relanzarse sola. Al final
   debe mostrarse la pantalla de inicio de sesión, con la última versión en la esquina
   superior derecha.
4. Al terminar, deja `version.py` como estaba (`git checkout -- bifrost-<flavour>/src/version.py`).

Instala la última release real sobre tu instalación, así que usa un equipo donde eso no
moleste. Si `flet build` no funciona en tu equipo, el build podría hacerse con GitHub
Actions, pero no se ha probado.

Esta forma solo sirve si la última release ya contiene el fichero que pide tu código. Si tu
cambio toca **lo que se publica** (nombres de los assets, el job `release` del CI) o **lo
que descarga el updater**, la última release todavía no lo tiene: usa la forma siguiente.

### Cómo probarlo: contra una prerelease de tu rama (antes del merge a `main`)

Sirve para probar de punta a punta, **sin hacer merge a `main` y sin que los usuarios lo
noten**, un cambio que afecta a la release o a la descarga del update. Se hizo así para pasar
el autoupdate de Windows del `.exe` al `.zip` (rama `feature/update`, prerelease `v1.0.330`).

**Por qué funciona y por qué es seguro:**

- El job `release` del CI solo se ejecuta en `main` y `release`, así que desde una rama
  normal no hay ninguna release que probar. Se habilita temporalmente para tu rama.
- La release de la rama se publica como **prerelease**. GitHub nunca marca una prerelease
  como `latest`, y las apps de los usuarios solo consultan `releases/latest`: no la ven y no
  se actualizan a ella.
- Tu build local se apunta a esa prerelease concreta (por su tag) en vez de a `latest`. Ese
  cambio solo existe en tu equipo y no se commitea.
- Se prueban así a la vez el CI nuevo (qué publica y con qué nombres) y el updater nuevo
  (qué descarga y cómo lo instala).

Lo que **no** queda aislado en tu rama: las releases y los tags son del repositorio, así que
la prerelease es visible en la página de *Releases* hasta que la borres.

#### 1. Publicar una prerelease desde tu rama

En `.github/workflows/main.yml`, job `release`, cambia temporalmente tres cosas (marca cada
línea con un comentario `TEMPORAL` para encontrarlas luego):

```yaml
  release:
    # TEMPORAL: <tu-rama> publica una prerelease. Revertir antes del merge a main.
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/release' || github.ref == 'refs/heads/<tu-rama>'
    ...
      - name: Crear GitHub Release
        with:
          ...
          prerelease: ${{ github.ref == 'refs/heads/<tu-rama>' }}   # TEMPORAL
          target_commitish: ${{ github.sha }}                       # TEMPORAL
```

- `if`: deja que el job `release` se ejecute en tu rama.
- `prerelease`: es lo que impide que la release sea `latest`. En `main` sigue valiendo `false`.
- `target_commitish`: sin él, GitHub crea el tag sobre la rama principal y no sobre tu
  commit, lo que confunde.

Haz un commit **solo con este cambio** (así se revierte fácil) y súbelo. Si usas PowerShell
5.1, escribe el mensaje en un fichero y usa `git commit -F fichero`: con varios `-m`,
PowerShell puede meterlos todos en el título.

#### 2. Comprobar la prerelease

Cuando termine la ejecución en *Actions* (todos los jobs en verde, incluido `release`):

1. En *Releases* debe aparecer `Release v1.0.<n>` con la etiqueta **Pre-release**. El número
   es el de la ejecución del workflow.
2. Revisa sus assets: deben estar los ficheros con los nombres que espera tu código (para
   Windows: `bifrost-<app>-<rama>-windows.exe` y `bifrost-<app>-windows.zip`). Si publicas un
   `.zip`, descárgalo y comprueba que contiene lo que debe.
3. Comprueba que `latest` **no** ha cambiado (debe salir la release anterior, no la tuya):

   ```powershell
   (Invoke-RestMethod https://api.github.com/repos/its-irb/irb-storage-public-scripts/releases/latest).tag_name
   ```

#### 3. Apuntar tu build local a la prerelease (sin commit)

- `bifrost-<flavour>/src/version.py`: una versión menor que la de la prerelease, p. ej.
  `0.0.1`. **Por qué:** el updater solo ofrece actualizar si la versión publicada es mayor
  que la instalada. Ojo: `2.0.0` es mayor que `1.0.<n>`, así que con la versión del repo no
  ofrecería nada.
- `shared/bifrost_backend/common/updates.py`: cambia `releases/latest` por el tag de tu
  prerelease en las dos URLs, y marca las líneas con `# PRUEBA LOCAL, no commitear`:

  ```python
  # check_update_version()
  requests.get(f"https://api.github.com/repos/{REPO}/releases/tags/v1.0.<n>", timeout=5)
  # download_new_binary()
  url = f"https://github.com/{REPO}/releases/download/v1.0.<n>/{file_name}{sufijo}"
  ```

  **Por qué:** `releases/latest` ignora las prereleases, así que sin este cambio tu build
  nunca la encontraría. Si el nombre del fichero que descarga el updater lleva la rama (como
  el `.exe` antiguo, `-main-windows.exe`), cambia también el sufijo en
  `get_update_file_suffix()` por el de tu rama. Con el `.zip` no hace falta: su nombre no
  lleva la rama.
- Comprueba que las URLs responden antes de compilar (deben dar `200` o `206`):

  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" -L -r 0-0 https://github.com/its-irb/irb-storage-public-scripts/releases/download/v1.0.<n>/bifrost-mount-windows.zip
  ```

#### 4. Compilar, comprobar e instalar

Compila como en "Compilar e instalar" (borrando antes la caché de Flet, ver "Trampas
conocidas"). Antes de instalar, comprueba que el build lleva tu código de prueba:

```powershell
Get-ChildItem $src -Recurse -Filter updates.py | Select-String "v1.0.<n>"
```

donde `$src` es `dist` o, si tuviste que usar el CMake de 64 bits,
`build\flutter\build\windows\x64\runner\Release`. Si no sale nada, estás a punto de probar
código viejo.

Instala con la app cerrada:

```powershell
Stop-Process -Name bifrost-<flavour> -ErrorAction SilentlyContinue
sudo robocopy "$src" "C:\Program Files (x86)\Bifrost-<flavour>" /MIR /NFL /NDL /NJH
```

`/MIR` deja la carpeta idéntica al build y borra lo que sobra, lo que evita la "instalación
mezclada". En robocopy, los códigos de salida de 0 a 7 son correctos.

#### 5. Probar la actualización

1. Abre la app desde el acceso directo. Debe ofrecer `New version available: v1.0.<n>`.
2. Pulsa *Update* y **no abras la app a mano**.
3. Debe instalarse y relanzarse sola, en la pantalla de inicio de sesión y con `1.0.<n>`
   arriba a la derecha.

Si el updater descarga un `.zip`, puedes confirmar que pasó por él: en `%TEMP%` debe quedar
una carpeta `bifrost-update-*` con el `.exe` extraído
(`Get-ChildItem $env:TEMP -Directory -Filter "bifrost-update-*" | Get-ChildItem`).

#### 6. Deshacer todo (no te lo saltes)

1. Quita las líneas `# PRUEBA LOCAL` de `updates.py` y restaura `version.py`
   (`git checkout -- bifrost-<flavour>/src/version.py`). Si `updates.py` también tiene
   cambios buenos sin commitear, no uses `git checkout` con él: deshaz solo esas líneas.
2. Quita del workflow las líneas `TEMPORAL` (o `git revert <commit del paso 1>`) **antes del
   merge a `main`**. Si llegaran a `main`, el `if` no haría daño, pero el workflow quedaría
   con código de prueba.
3. Borra la prerelease en *Releases* (icono de papelera) y después su tag, que no se borra
   con ella: `git push origin --delete v1.0.<n>`.
4. Comprueba que `latest` sigue siendo la release anterior.

### Compilar e instalar (Windows)

Requisitos: **Modo de desarrollador** activado (Flutter necesita enlaces simbólicos),
**Visual Studio Build Tools** con la carga "Desarrollo para el escritorio con C++" y
**Git Bash** en el PATH para `windows-assets-downloader.sh`.

```powershell
cd bifrost-<flavour>\src ; bash ../../shared/windows-assets-downloader.sh ; cd ..
uv sync --reinstall-package bifrost-shared
uv run flet build windows --output dist --no-rich-output
```

La app se instala en `C:\Program Files (x86)\Bifrost-<flavour>\` (es la ruta que relanza el
`.bat`): copia el **contenido** de la carpeta de salida, no la carpeta en sí, de modo que
`bifrost-<flavour>.exe` quede en la raíz. Necesita permisos de administrador. Con la app
cerrada:

```powershell
sudo robocopy "<carpeta de salida>" "C:\Program Files (x86)\Bifrost-<flavour>" /MIR /NFL /NDL /NJH
```

### Trampas conocidas

- **Caché de Flet desactualizada.** Flet reutiliza `bifrost-<flavour>/build/site-packages`
  mientras no cambie `build/.hash`, y ese hash no depende del código de `shared/`. Tras
  cambiar `shared/`, borra ambos antes de compilar, y comprueba que el build lleva tu
  cambio mirando `Release\site-packages\...` (si no, estás probando código viejo).
- **Fallo `vcruntime140_1.dll` en el último paso.** Visto con Build Tools 2022 17.14: su
  `cmake.exe` es de 32 bits y Windows redirige `System32` a `SysWOW64`, donde no existe esa
  DLL (y las otras dos del runtime se copian en su versión de 32 bits, incorrecta junto a un
  Python x64). El build falla en el paso `INSTALL`. Solución: ejecutar ese paso con un CMake
  de 64 bits desde `build\flutter\build\windows\x64`:
  `<cmake-x64>\bin\cmake.exe -DBUILD_TYPE=Release -P cmake_install.cmake`
  y comprobar que `vcruntime140.dll` y `msvcp140.dll` son x64.
- **Instalación mezclada.** Si actualizas sobre un build copiado a mano, Inno Setup no
  sobrescribe los ficheros sin versión (`.py`) cuya copia local es más reciente que la de la
  release. La carpeta queda con la versión de la release en `app.zip` pero con código de tu
  build. Para pruebas limpias, vuelve a copiar el build antes de cada intento.
