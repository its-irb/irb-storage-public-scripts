# BIFROST
**Herramienta de transferencia de datos a MinIO S3 — IRB Barcelona**

---

## Qué hace

BIFROST te permite:
- Copiar datos desde carpetas de red (SMB/CIFS) o tu local a buckets de MinIO S3, con verificación de integridad y etiquetado automático de metadatos en cada objeto transferido
- Montar carpetas de MinIO S3 como unidad local en tu ordenador

---

## Requisitos

**No hace falta instalar rclone.** El ejecutable ya lo lleva incluido y usa el suyo propio — si tienes rclone instalado en tu ordenador, no pasa nada, el programa lo ignora.

**macOS:** fuse-t se instala automáticamente la primera vez que ejecutas BIFROST (requiere Homebrew). Si tienes macFUSE instalado, **desinstálalo primero** para que rclone pueda usar fuse-t correctamente:
```bash
brew uninstall macfuse
```
**Estar conectado a la VPN de Nexica** (Forticlient)
**Tener tkinter instalado**: Esto ya no será necesario en las proximas versiones

---

## Archivos

| Archivo | Función |
|---|---|
| `bifrost.py` | Interfaz gráfica (tkinter). Punto de entrada. |
| `backend.py` | Toda la lógica de negocio (LDAP, rclone, SMB, S3). |
| `minio-sts-credentials-request.py` | Genera credenciales temporales de acceso al servidor de Minio de IRB Barcelona.|

---

## Cómo ejecutar

```bash
python3 bifrost.py
```

Para iniciar sesión con un usuario distinto al del sistema:
```bash
python3 bifrost.py --customuser
```

Para lanzar forzar la auto-actualización:
```bash
python3 bifrost.py --update
```

