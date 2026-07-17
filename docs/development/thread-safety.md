# Thread-safety con Flet — BIFROST

La regla más importante del repositorio. La mayoría de bugs difíciles de Bifrost han venido de violarla.

## Regla absoluta

> **Toda mutación de `control.controls` o llamada a `page.update()` desde fuera del event loop de Flet debe envolverse en `backend.ui_call(page, fn)`.**

Los únicos sitios donde se puede llamar `page.update()` directamente son los event handlers de Flet (botones, diálogos, `on_click`, `on_change`, …) porque Flet los ejecuta ya como tareas asyncio.

## El bug `IndexError: list index out of range`

### Síntoma

```
Unhandled error in 'on_app_lifecycle_state_change' handler
...
File "object_patch.py", line 889, in _compare_lists
    target_key = dst_keys[i]
                 ~~~~~~~~^^
IndexError: list index out of range
```

Ocurría al cambiar el foco de la pestaña del navegador durante una copia, y especialmente al iniciar una copia (el botón Copy refresca el browser de destino).

### Causa raíz

Flet mantiene un "snapshot" del árbol de controles anterior y, en cada evento, calcula un diff (`ObjectPatch.from_diff`) para enviar solo los cambios al cliente. Ese diff recorre las listas `controls` **en el thread del event loop asyncio, sin ningún lock**.

El código original usaba `page.run_thread(fn)` para todas las actualizaciones de UI desde hilos de background (callbacks de log, browser de carpetas, etc.). `run_thread` lanza `fn()` en un `ThreadPoolExecutor` que se ejecuta **en paralelo real** con el event loop asyncio.

La colisión:

```
asyncio event loop (diff walker):   cuenta controls: 0, 1, 2, 3, 4...
ThreadPoolExecutor worker:                                  ← controls.clear()
asyncio event loop (diff walker):                    ...5? → CRASH (lista vacía)
```

El GIL de Python **no ayuda** aquí porque la iteración del diff y `.clear()` abarcan múltiples opcodes de bytecode entre los cuales el GIL puede cambiar de hilo.

### Solución

Se reemplazó `page.run_thread(fn)` por `page.run_task(async_wrapper)` en `ui_call`:

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    # Guard: skip UI updates if WebSocket connection is closed (OOD reconnection)
    if not page.session or not page.session.connection:
        print(f"[ui_call] Skipping UI update — session disconnected", flush=True)
        return

    async def _wrapper():
        fn()
    page.run_task(_wrapper)
```

`page.run_task` usa `asyncio.run_coroutine_threadsafe(coro, loop)`, que encola la coroutine en el **mismo event loop single-threaded** donde corre el diff walker. Asyncio es cooperativo: una coroutine solo cede en un `await`. Como `_compare_lists` **no contiene ningún `await`**, no puede ser interrumpida por una coroutine encolada → el diff siempre ve una lista estable.

### Correcciones adicionales

Dos llamadas a `threading.Timer` que invocaban directamente funciones de navegación de carpetas sin pasar por `ui_call` se corrigieron:

```python
# Antes (incorrecto — el hilo del timer muta controls directamente):
threading.Timer(0.1, dest_browser_refresh).start()
threading.Timer(0.1, refresh_fn).start()

# Después (correcto — encolado en asyncio):
threading.Timer(0.1, lambda: ui_call(page, dest_browser_refresh)).start()
threading.Timer(0.1, lambda: ui_call(page, refresh_fn)).start()
```

## `safe_thread(page, target, daemon=True)`

```python
def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    def _wrapper():
        try:
            target()
        except Exception as exc:
            tb = traceback.format_exc()
            print(f"[safe_thread] Unhandled exception:\n{tb}")
            _exc = exc
            def _show(e=_exc):
                show_dialog(page, "Unexpected error",
                            f"{type(e).__name__}: {e}\n\nCheck console or contact ITS.", C_ERROR)
            ui_call(page, _show)
    t = threading.Thread(target=_wrapper, daemon=daemon)
    return t
```

Crea un `threading.Thread` que envuelve `target` con try/except y muestra cualquier excepción en un diálogo vía `ui_call`. **Preferir frente a `threading.Thread` directo** para acciones de usuario. Devuelve el thread (hay que llamar `.start()`).

## Cuándo usar qué

| Situación | Mecanismo |
|---|---|
| Event handler de Flet (`on_click`, `on_change`, …) | directo, `page.update()` sin wrapper |
| Mutación de UI desde hilo de background | `ui_call(page, fn)` |
| Lanzar trabajo de usuario en background | `safe_thread(page, target).start()` |
| `threading.Timer` que mute UI | `threading.Timer(delay, lambda: ui_call(page, fn)).start()` |
| Callback de log de rclone (web) | pasar `log_fn` que internally usa `_dispatch_log` → `ui_call` |
| Callback de log de rclone (desktop) | pasar `log_fn` que usa `ui_call(page, _add)` |

## Anti-patrones

- `page.run_thread(fn)` para mutar UI — **prohibido**. Usar `ui_call`.
- `threading.Timer(delay, fn)` donde `fn` muta `controls` — envolver en `lambda: ui_call(page, fn)`.
- `log_list.controls.append(...)` desde un hilo — pasar por el canal de logs adecuado.
- Asumir que el GIL protege operaciones multi-opcode — no es así.
- Llamar `page.update()` tras comprobar `page.session.connection` a mano — `ui_call` ya lo hace.

## Verificación

Si aparece `IndexError: list index out of range` en `object_patch.py:_compare_lists`, buscar mutaciones de UI fuera de `ui_call` en el código nuevo. El patrón típico es un callback de un hilo de rclone, un timer, o un `ThreadPoolExecutor` que toca `controls` directamente.
