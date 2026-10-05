# Documentación para usuarios — BIFROST

BIFROST es un conjunto de aplicaciones del IRB Barcelona para trabajar con MinIO (S3): copiar datos a los buckets, etiquetarlos con metadatos y
montar carpetas S3 como unidades locales.

Elige la guía según lo que quieres conseguir:

| Objetivo | Guía |
|---|---|
| Instalar BIFROST y empezar a usarlo | [getting-started.md](getting-started.md) |
| Copiar datos a un bucket, con verificación y metadatos | [transfer-data.md](transfer-data.md) |
| Etiquetar o corregir metadatos de ficheros ya subidos (sin re-subir) | [tag-manager.md](tag-manager.md) |
| Montar una carpeta de un bucket como unidad local | [mount-buckets.md](mount-buckets.md) |
| Usar BIFROST desde el navegador en el clúster (Open OnDemand) | [web-mode-ood.md](web-mode-ood.md) |
| Resolver problemas (no conecta, no inicia, etc.) | [troubleshooting.md](troubleshooting.md) |

## Requisitos comunes

- **VPN de Nexica** (Forticlient) activa.
- Cuenta de usuario del IRB. 
- En Windows, **bifrost-mount** necesita además **WinFsp** (la app ofrece
  instalarlo automáticamente si falta; ver [mount-buckets.md](mount-buckets.md)).

## ¿Cuál de las dos aplicaciones uso?

- **bifrost-transfer** → copiar datos *a* MinIO (o re-etiquetarlos).
- **bifrost-mount** → *abrir* directamente un bucket de MinIO como si
  fuera una unidad del equipo.

Ambas comparten login y la selección del servidor MinIO; la diferencia está
en la vista final (copia vs. montado).

## Notas

- Los nombres de usuario, servidores y buckets son los que corresponden a tu
  grupo de trabajo en el IRB; si no ves el servidor o el bucket que esperas,
  es probable que no tengas acceso (ver [troubleshooting.md](troubleshooting.md)).
- Para detalles técnicos (arquitectura, build, CI) consulta
  [../development/README.md](../development/README.md).
