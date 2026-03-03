// src/modules/logging.rs
// ✅ Módulo de logging/auditoría para el sistema SCORE
#![allow(dead_code)] 
use sqlx::PgPool;
use log::{info, error};

// ✅ Estructura para registrar un log de auditoría
pub struct LogEntry {
    pub id_tipo_accion: i32,      // Categoría: 1=SESIÓN, 2=USUARIOS, 3=CONSULTAS
    pub id_accion: i32,           // Acción específica (ver tabla acciones)
    pub id_usuario: i32,          // Usuario que realizó la acción
    pub accion: String,           // Nombre de la acción (snapshot)
    pub cedula_relacionada: Option<i32>,  // Cédula involucrada (NULL si no aplica)
    pub ip_origen: String,        // IP de origen
    pub user_agent: String,       // User-Agent del navegador
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
    .bind(entry.id_usuario)
    .bind(&entry.accion)
    .bind(&entry.cedula_relacionada)
    .bind(&entry.ip_origen)
    .bind(&entry.user_agent)
    .execute(pool)
    .await
    {
        Ok(_) => {
            info!("✅ Log registrado: {} - Usuario: {} - IP: {}", 
                  entry.accion, entry.id_usuario, entry.ip_origen);
            Ok(())
        }
        Err(e) => {
            // ⚠️ IMPORTANTE: No propagar el error, solo loguear
            // El logging no debe romper la funcionalidad principal
            error!("❌ Error registrando log (no crítico): {}", e);
            Err(e)  // Retornamos error pero el caller puede ignorarlo
        }
    }
}

// ✅ Helper para extraer IP del request (MEJORADO)
pub fn extract_ip(req: &actix_web::HttpRequest) -> String {
    // 1. Intentar con X-Forwarded-For (proxy/load balancer)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(ip) = forwarded.to_str() {
            return ip.split(',').next().unwrap_or("unknown").trim().to_string();
        }
    }
    
    // 2. Intentar con X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.trim().to_string();
        }
    }
    
    // 3. Obtener IP directa de la conexión (localhost, desarrollo)
    if let Some(peer_addr) = req.peer_addr() {
        return peer_addr.ip().to_string();
    }
    
    "unknown".to_string()
}

// ✅ Helper para extraer User-Agent del request (ACTUALIZADO)
pub fn extract_user_agent(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

// ✅ Funciones helper para crear LogEntry más fácilmente

/// Log de inicio de sesión
pub fn log_login(usuario_id: i32, cedula: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 1,
        id_accion: 1,
        id_usuario: usuario_id,
        accion: "INICIO DE SESIÓN".to_string(),
        cedula_relacionada: Some(cedula),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de cierre de sesión
pub fn log_logout(usuario_id: i32, cedula: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 1,
        id_accion: 2,
        id_usuario: usuario_id,
        accion: "CIERRE DE SESIÓN".to_string(),
        cedula_relacionada: Some(cedula),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de crear usuario
pub fn log_crear_usuario(autor_id: i32, cedula_nuevo: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 3,
        id_usuario: autor_id,
        accion: "CREAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_nuevo),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de editar usuario
pub fn log_editar_usuario(autor_id: i32, cedula_editado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 4,
        id_usuario: autor_id,
        accion: "EDITAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_editado),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de eliminar usuario
pub fn log_eliminar_usuario(autor_id: i32, cedula_eliminado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 5,
        id_usuario: autor_id,
        accion: "ELIMINAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_eliminado),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de bloquear/activar usuario
pub fn log_bloquear_usuario(autor_id: i32, cedula_bloqueado: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 2,
        id_accion: 6,
        id_usuario: autor_id,
        accion: "BLOQUEAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula_bloqueado),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de exportar PDF
pub fn log_exportar_pdf(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 9,
        id_usuario: usuario_id,
        accion: "EXPORTAR PDF".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de consultar movimientos RE
pub fn log_movimientos_re(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 10,
        id_usuario: usuario_id,
        accion: "MOVIMIENTOS RE".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

/// Log de consultar votos a emitir
pub fn log_votos_emitir(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 11,
        id_usuario: usuario_id,
        accion: "VOTOS A EMITIR".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}