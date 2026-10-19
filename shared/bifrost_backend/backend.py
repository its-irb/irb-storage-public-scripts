"""Fachada de compatibilidad: reexporta la API del backend dividido en módulos.

Las apps y el frontend siguen usando ``backend.X``; el código vive en
``common/``, ``mount/`` y ``transfer/``.
"""

from __future__ import annotations

from .common.constants import (
    MINIO_SERVERS,
    DEFAULT_S3_REGION,
    REPO,
    __version__,
    EMOJI_FONT_FILENAME,
    LDAP_SERVER_URL,
    LDAP_BASE_DN,
)
from .common.rclone import (
    get_rclone_executable,
    obtener_ruta_rclone_conf,
    rclone_lsd,
)
from .common.auth import (
    get_credentials,
    configure_rclone,
    get_session_info,
    validar_credenciales_ldap,
)
from .common.updates import (
    check_update_version,
    should_check_for_updates,
    get_update_file_suffix,
    download_new_binary,
    get_emoji_font_asset_path,
)
from .common.ui_helpers import (
    ui_call,
    safe_thread,
)
from .common.logs import (
    setup_logging,
)
from .mount.s3_mount import (
    mount_rclone_S3_prefix_to_folder,
    desmontar_punto_montaje,
    resolver_mount_point_destino,
    desmontar_todos_los_mounts_s3,
)
from .mount.preflight import (
    WinFspMissingError,
    install_winfsp_windows,
)
from .transfer.rclone_ops import (
    rclone_lsjson,
    rclone_list_files_only,
    list_prefix_contents,
    obtener_num_cpus,
    traducir_ruta_a_remote,
)
from .transfer.ldap_groups import (
    get_ldap_groups,
)
from .transfer.s3_tags import (
    get_s3_client_from_profile,
    get_object_tags,
    apply_tags_to_prefix,
    apply_tags_to_object,
    get_bucket_tags,
    construir_tag_string,
)
from .transfer.smb import (
    EXCEPCION_FILERS,
    construir_credenciales_smb,
    obtener_shares_accesibles,
    obtener_perfiles_rclone_config,
    crear_perfil_rclone_smb,
    actualizar_password_perfiles_rclone,
    obtener_letra_unidad_disponible,
    generar_punto_montaje,
    montar_share_rclone,
    desmontar_todos_los_shares,
    configurar_perfiles_smb_si_faltan,
    montar_shares_seleccionados,
    construir_recursos_cifs_dict,
)
from .transfer.sftp import (
    crear_perfil_rclone_sftp,
    eliminar_perfil_rclone,
    limpiar_perfiles_rclone_con_prefijo,
    generar_nombre_perfil_sftp,
    validar_conexion_sftp,
)
from .transfer.copy_check import (
    ejecutar_rclone_copy,
    ejecutar_rclone_check,
    es_directorio_rclone,
    traducir_a_ruta_local_montada,
    preparar_origen_para_check,
)
