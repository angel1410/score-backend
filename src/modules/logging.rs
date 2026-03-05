// src/modules/logging.rs
// ✅ Módulo de logging/auditoría para el sistema SCORE
#![allow(dead_code)] 
use sqlx::PgPool;
use log::{info, error};

// ✅ Estructura para registrar un log de auditoría
pub struct LogEntry {
    pub id_tipo_accion: i32,
    pub id_accion: i32,
    pub id_usuario: Option<i32>,
    pub accion: String,
    pub cedula_relacionada: Option<i32>,
    pub ip_origen: String,
    pub user_agent: String,
}

// ✅ Función principal para insertar log en la BD
pub async fn registrar_log(pool: &PgPool, entry: LogEntry) -> Result<(), sqlx::Error> {
    match sqlx::query(
        r#"
        INSERT INTO logs (id_tipo_accion, id_accion, id_usuario, accion, cedula_relacionada, ip_origen, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(entry.id_tipo_accion)
    .bind(entry.id_accion)
    .bind(&entry.id_usuario)
    .bind(&entry.accion)
    .bind(&entry.cedula_relacionada)
    .bind(&entry.ip_origen)
    .bind(&entry.user_agent)
    .execute(pool)
    .await
    {
        Ok(_) => {
            info!("✅ Log registrado: {} - Usuario: {:?}", entry.accion, entry.id_usuario);
            Ok(())
        }
        Err(e) => {
            error!("❌ Error registrando log (no crítico): {}", e);
            Err(e)
        }
    }
}

// ✅ Helper para extraer IP del request
pub fn extract_ip(req: &actix_web::HttpRequest) -> String {
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(ip) = forwarded.to_str() {
            return ip.split(',').next().unwrap_or("unknown").trim().to_string();
        }
    }
    
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.trim().to_string();
        }
    }
    
    if let Some(peer_addr) = req.peer_addr() {
        return peer_addr.ip().to_string();
    }
    
    "unknown".to_string()
}

// ✅ Helper para extraer User-Agent del request
pub fn extract_user_agent(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

// =====================
// Funciones helper para LOGS DE USUARIOS (id_tipo_accion = 2)
// =====================

pub fn log_crear_usuario(autor_id: i32, cedula_nuevo: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 3,
        id_usuario: Some(autor_id),
        accion: "CREAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_nuevo),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_editar_usuario(autor_id: i32, cedula_editado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 4,
        id_usuario: Some(autor_id),
        accion: "EDITAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_editado),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_eliminar_usuario(autor_id: i32, cedula_eliminado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 5,
        id_usuario: Some(autor_id),
        accion: "ELIMINAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_eliminado),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_bloquear_usuario(autor_id: i32, cedula_bloqueado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 6,
        id_usuario: Some(autor_id),
        accion: "BLOQUEAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_bloqueado),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_desbloquear_usuario(autor_id: i32, cedula_desbloqueado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 12,
        id_usuario: Some(autor_id),
        accion: "DESBLOQUEAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_desbloqueado),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_carga_masiva(autor_id: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 7,
        id_usuario: Some(autor_id),
        accion: "CARGA MASIVA DE USUARIOS".to_string(),
        cedula_relacionada: None,
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_reactivar_usuario(autor_id: i32, cedula_reactivado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 13,
        id_usuario: Some(autor_id),
        accion: "REACTIVAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_reactivado),
        ip_origen: ip,
        user_agent: ua,
    }
}

// =====================
// Funciones helper para LOGS DE CONSULTAS (id_tipo_accion = 3)
// =====================

pub fn log_exportar_pdf(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 9,  // ✅ EXPORTAR PDF
        id_usuario: Some(usuario_id),
        accion: "EXPORTAR PDF".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_movimientos_re(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 10,  // ✅ MOVIMIENTOS RE
        id_usuario: Some(usuario_id),
        accion: "MOVIMIENTOS RE".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_votos_emitir(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 11,  // ✅ VOTOS A EMITIR
        id_usuario: Some(usuario_id),
        accion: "VOTOS A EMITIR".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

pub fn log_consultar_datos_elector(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 14,  // ✅ CONSULTAR DATOS ELECTOR (NUEVO)
        id_usuario: Some(usuario_id),
        accion: "CONSULTAR DATOS ELECTOR".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}