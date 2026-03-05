// mod.rs
pub mod login;
pub mod re;
pub mod ac;
pub mod users;
pub mod logging; 

pub use login::{get_login, get_logout, get_captcha}; // ✅ Nuevo endpoint
pub use re::{get_movimientos_re, get_elector, get_electores, get_votos_emitir}; // ✅ NUEVO
pub use ac::get_usuario_by_ac;

pub use users::{
    get_usuarios,
    get_usuarios_eliminados,
    crear_usuario,
    actualizar_usuario,
    bloquear_usuario,
    eliminar_usuario,
    reactivar_usuario,
    carga_masiva,
    get_roles
};