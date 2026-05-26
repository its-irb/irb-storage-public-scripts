---
type: decision
tags: [build, packaging, shared]
fuentes: []
actualizado: 2026-05-18
---

# Wheel local `bifrost-shared` con `__BUILDPATH__`

## Resumen

El paquete `bifrost-shared` (código común backend/frontend en `shared/`) se distribuye a `bifrost-mount` y `bifrost-transfer` como **wheel local construido en build-time**, no como dependencia desde PyPI ni como path editable. El `pyproject.toml` de cada app referencia el wheel con un placeholder `__BUILDPATH__` que el script de build sustituye por la ruta real del `.whl` antes de invocar `flet build`, y revierte al terminar.

## Detalle

Cada app tiene en su `pyproject.toml` una línea del tipo:

```toml
"bifrost-shared @ file:///__BUILDPATH__/shared"
```

El flujo de build (ver `build-local.ps1` y `.github/workflows/main.yml`):

1. `python -m build shared/ --outdir <app>/` → genera `bifrost_shared-<version>-py3-none-any.whl` dentro de la carpeta de la app.
2. Sustituir `__BUILDPATH__/shared` por la ruta absoluta al `.whl` recién generado en `<app>/pyproject.toml`.
3. `flet build <plataforma>` empaqueta usando ese wheel.
4. Revertir el `pyproject.toml` al placeholder para no contaminar el repo.

### Por qué este patrón y no otros

- **PyPI público**: no aplica, el código es interno y específico de IRB Barcelona; no merece publicarse.
- **Path editable (`-e ../shared`)**: `flet build` no resuelve bien instalaciones editables al congelar dependencias en el binario, y las dos apps necesitan que el código se empaquete dentro del bundle.
- **Dependencia git/submódulo**: complica el clon y la CI (necesita credenciales) sin ganar nada — el código vive en el mismo repo.
- **Copia/sync del código a cada app**: rompería la única fuente de verdad de [[shared/bifrost_backend/backend.py]] y obligaría a sincronizar a mano.

El wheel local construido on-demand da una única fuente de verdad (`shared/`), funciona con `flet build` (que solo entiende dependencias estándar), y permite congelar la versión del shared en cada build sin que las apps tengan referencias a paths arbitrarios del sistema de la usuaria.

### Implicaciones operativas

- **No commitear** `<app>/pyproject.toml` con el path sustituido. El script revierte al final, pero conviene revisarlo antes de commitear.
- **Dev local** funciona sin tocar `pyproject.toml`: cada app instala `-r ../shared/requirements.txt` en su venv (`flet run` no construye wheels).
- Para añadir/cambiar deps en `shared/`, regenerar `shared/pyproject.toml` y `shared/requirements.txt` y rebuilear ambas apps.

## Fuentes

- `build-local.ps1` (raíz del repo) — implementación del flujo de sustitución.
- `.github/workflows/main.yml` — mismo flujo en CI para macOS y Windows.
- `CLAUDE.md` — sección "Build / empaquetar".
