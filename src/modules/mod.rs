// src/modules/mod.rs
pub mod login;
pub mod re;
pub mod ac;
pub mod users;
pub mod logging;
pub mod logs;
pub mod parametros;
pub mod security;
pub mod exportacion;  // ✅ Módulo consolidado de exportación/verificación

// ✅ Login
pub use login::{get_login, get_logout, get_captcha};

// ✅ Registro Electoral (RE)
pub use re::{get_movimientos_re, get_elector, get_electores, get_votos_emitir};

// ✅ Archivo de Cedulados (AC)
pub use ac::get_usuario_by_ac;

// ✅ Logs de Auditoría
// pub use logs::{get_logs, get_logs_resumen, get_carga_masiva_id_by_log};

// ✅ Usuarios (CRUD + Carga Masiva)
pub use users::{
    get_usuarios,
    get_roles,
    crear_usuario,
    actualizar_usuario,
    bloquear_usuario,
    eliminar_usuario,
    reactivar_usuario,
    validar_carga_masiva,
    confirmar_carga_masiva,
    descargar_plantilla,
    descargar_carga_masiva_excel,
};

// ✅ Parámetros (CRUD)
pub use parametros::{
    get_parametros,
    get_parametro_by_nombre,
    crear_parametro,
    actualizar_parametro,
    eliminar_parametro,
    get_fecha_cierre,
};

// ✅ Exportación y Verificación de documentos (CONSOLIDADO)
pub use exportacion::{registrar_exportacion, verificar_documento};
