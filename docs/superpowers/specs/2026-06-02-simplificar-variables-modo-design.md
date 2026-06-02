# Spec: Simplificación de variables de modo (IS_WEB / IS_LINUX_CLUSTER)

**Fecha:** 2026-06-02
**Autor:** ona.perez@irbbarcelona.org
**Estado:** Aprobado

---

## Contexto

El repositorio BIFROST contiene dos apps Flet:

- **bifrost-transfer** — copia datos a MinIO S3. Tiene dos modos: desktop y web (Open OnDemand).
- **bifrost-mount** — monta buckets MinIO como unidad local. Solo modo desktop.

Antes de este cambio, la detección de modo en bifrost-transfer usaba tres variables y dos env vars:

```python
DEV_WEB = os.environ.get("BIFROST_DEV") == "1"
IS_WEB  = ("--web" in sys.argv) or (__name__ != "__main__") or DEV_WEB
IS_LINUX_CLUSTER = (...) or os.environ.get("BIFROST_CLUSTER") == "1"
```

Y bifrost-mount usaba:

```python
IS_LINUX_CLUSTER = (...) or os.environ.get("BIFROST_LINUX") == "1"
```

La semántica estaba solapada (`IS_WEB` y `IS_LINUX_CLUSTER` eran conceptualmente lo mismo en transfer), y bifrost-mount tenía un flujo CIFS de cluster que se va a mover a bifrost-transfer web en el futuro.

---

## Decisión de diseño

### bifrost-transfer: una sola variable `IS_WEB`

```python
# Modo web: producción (BIFROST_CLUSTER=1), importado por Flet web, o dev local (--web)
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- `DEV_WEB` se elimina.
- `BIFROST_DEV` se elimina. Para desarrollo web se usa `flet run --web`.
- `IS_LINUX_CLUSTER` se elimina. Todo el código que la leía pasa a leer `IS_WEB`.
- La funcionalidad CIFS (montar shares) siempre es parte del modo web, no un flag independiente.

**Flujo de ejecución resultante:**

| Caso | Comando |
|---|---|
| transfer desktop (dev / prod) | `flet run` |
| transfer web (dev) | `flet run --web` |
| transfer web (prod, via OOD) | `BIFROST_CLUSTER=1 python src/main.py` |

`BIFROST_CLUSTER=1` es la señal de producción para activar `IS_WEB`. Desde el punto de vista del código, ambos mecanismos producen exactamente el mismo resultado.

### bifrost-mount: sin variables de modo

- `IS_LINUX_CLUSTER` se elimina.
- `BIFROST_LINUX` se elimina.
- Todo el código condicional sobre `IS_LINUX_CLUSTER` en bifrost-mount se elimina: la sección CIFS de `view_mount` (checkboxes de shares, botón de credenciales de admin) y cualquier lógica de backend que solo se invoque desde ese bloque.
- bifrost-mount queda con un único modo: desktop estándar.

---

## Alcance de cambios

### `bifrost-transfer/src/main.py`
- Eliminar `DEV_WEB` y su comentario.
- Reescribir `IS_WEB` con la nueva condición.
- Eliminar `IS_LINUX_CLUSTER` y su comentario.
- Sustituir todas las referencias a `IS_LINUX_CLUSTER` por `IS_WEB`.

### `bifrost-mount/src/main.py`
- Eliminar `IS_LINUX_CLUSTER` y su comentario.
- Eliminar todo el código condicional sobre `IS_LINUX_CLUSTER`: sección CIFS en `view_mount`, checkboxes de shares, botón de admin, y llamadas de backend exclusivas de ese flujo.

### `CLAUDE.md`
- Eliminar filas de `BIFROST_DEV` y `BIFROST_LINUX` de la tabla de variables de entorno.
- Actualizar la fila de `BIFROST_CLUSTER`: activa `IS_WEB` (modo web completo, incluirá CIFS en el futuro).
- Actualizar la sección de flags útiles de desarrollo.

---

## Fuera de scope (tarea futura)

Añadir la funcionalidad de montar shares CIFS a la vista web de bifrost-transfer (equivalente al botón que existía en bifrost-mount). Esto se diseñará e implementará por separado.

---

## Variables de entorno resultantes

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa modo web (`IS_WEB=True`) — señal de producción OOD |
| `FLET_ASSETS_DIR` | ambas | Setado por Flet en runtime; el backend lo usa para localizar rclone |
| `FLET_APP_STORAGE_TEMP` | ambas | Setado por Flet; usado para debug de binarios |

Variables eliminadas: `BIFROST_DEV`, `BIFROST_LINUX`.