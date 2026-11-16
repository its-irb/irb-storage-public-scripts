# Tests y validación

Punto de partida para probar BIFROST: qué hay automatizado, cómo ejecutarlo y cómo
comprobar a mano lo que los tests no pueden cubrir.

> **Esto no es una guía de pautas.** Aún no se han definido criterios de testing para el
> proyecto (qué se prueba, con qué herramientas, con qué estructura). Lo que hay aquí es lo
> que se hizo al empezar con el autoupdate, y está sujeto a cambios. Donde aparece una
> recomendación, es una sugerencia, no una norma acordada.

## Estado actual

- Hay **tests automáticos (pytest) solo para el autoupdate**
  (`shared/bifrost_backend/common/updates.py`).
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
`bifrost-<flavour>.exe` quede en la raíz. Necesita permisos de administrador.

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
