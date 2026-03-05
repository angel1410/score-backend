// src/modules/mod.rs
pub mod login;
pub mod re;
pub mod ac;
pub mod users;
pub mod logging; 
pub mod logs;

pub use login::{get_login, get_logout, get_captcha};
pub use re::{get_movimientos_re, get_elector, get_electores, get_votos_emitir};
pub use ac::get_usuario_by_ac;
// ✅ ELIMINADO: pub use logs::{get_logs, get_logs_resumen}; (no se usa)

pub use users::{
    descargar_plantilla,
    get_usuarios,
    crear_usuario,
    actualizar_usuario,
    bloquear_usuario,
    eliminar_usuario,
    reactivar_usuario,
    carga_masiva,
    get_roles
};