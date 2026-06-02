---
type: decision
tags: [bifrost-transfer, bifrost-mount, variables-entorno, modo-web]
fuentes: [docs/superpowers/specs/2026-06-02-simplificar-variables-modo-design.md]
actualizado: 2026-06-02
---

# Variables de modo: unificación en IS_WEB

## Resumen

Se eliminaron `IS_LINUX_CLUSTER` y `DEV_WEB` de bifrost-transfer, fusionándolas en una única variable `IS_WEB`. En bifrost-mount, `IS_LINUX_CLUSTER` se eliminó completamente junto con el bloque CIFS (se moverá a bifrost-transfer web en una tarea futura). La env var `BIFROST_CLUSTER=1` pasa a ser la señal canónica de producción para modo web.

## Detalle

### Por qué se fusionaron IS_WEB e IS_LINUX_CLUSTER en transfer

Ambas variables eran semánticamente equivalentes: la app se despliega en producción en Linux cluster vía Open OnDemand, siempre en modo web. Tenerlas separadas obligaba a mantener dos condiciones sincronizadas que siempre tenían el mismo valor en producción:

```python
# Antes
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__")
IS_LINUX_CLUSTER = os.environ.get("BIFROST_CLUSTER") == "1"

# Ahora
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

### Por qué desaparece BIFROST_DEV

Se usaba para simular modo web en local sin el flag `--web` de Flet:

```python
# Antes
BIFROST_DEV = os.environ.get("BIFROST_DEV") == "1"
IS_WEB = ... or BIFROST_DEV
```

Con `flet run --web` disponible, la variable adicional era redundante. El entorno de desarrollo se alínea así con lo que hace Flet de forma nativa.

### Por qué desaparece IS_LINUX_CLUSTER de bifrost-mount

El flujo CIFS de cluster se moverá a bifrost-transfer web (tarea futura). Por ahora se elimina de mount, que queda con un único modo: desktop estándar.

```python
# Antes (bifrost-mount)
IS_LINUX_CLUSTER = os.environ.get("BIFROST_LINUX") == "1"
# ... bloque condicional CIFS/shares basado en IS_LINUX_CLUSTER ...

# Ahora
# (bloques CIFS eliminados)
```

### Señal de producción

`BIFROST_CLUSTER=1` sigue siendo la env var que activa `IS_WEB=True` en bifrost-transfer. La lanza el script de Open OnDemand en el cluster de Linux.

### Variable de token JWT en sección OOD

En la sección que valida tokens JWT, la condición cambió:

```python
# Antes
if not DEV_WEB:
    # Validar token...

# Ahora
if "--web" not in sys.argv:
    # Validar token...
```

La validación del token se salta cuando Flet lanza en modo dev (`--web` en argv) y se aplica en producción (`BIFROST_CLUSTER=1`, que no pasa `--web` a `sys.argv` pero sí entra por la rama del env var en `IS_WEB`).

## Fuentes

- `docs/superpowers/specs/2026-06-02-simplificar-variables-modo-design.md` — spec completo con decisión y alcance.
- `bifrost-transfer/src/main.py` — implementación.
- `bifrost-mount/src/main.py` — eliminación de `IS_LINUX_CLUSTER` y bloque CIFS.
