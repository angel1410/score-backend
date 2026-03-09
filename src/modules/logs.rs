// src/modules/logs.rs
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use crate::structs::AppState;

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct LogEntryResponse {
    pub id: i32,
    pub id_tipo_accion: i32,
    pub id_accion: i32,
    pub id_usuario: Option<i32>,
    pub accion: String,
    pub cedula_relacionada: Option<i32>,
    pub ip_origen: String,
    pub user_agent: String,
    pub created_at: chrono::NaiveDateTime,
    pub username: Option<String>,
    pub nombre_rol: Option<String>,
}

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct LogResumen {
    pub id_accion: i32,
    pub accion: String,
    pub total: i64,
}

#[derive(Deserialize, Debug)]
pub struct LogFilters {
    pub id_usuario: Option<i32>,
    pub id_tipo_accion: Option<i32>,
    pub id_accion: Option<i32>,
    pub cedula_relacionada: Option<i32>,
    pub fecha_desde: Option<String>,
    pub fecha_hasta: Option<String>,
    pub accion: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

pub async fn get_logs(
    app_state: web::Data<AppState>,
    filters: web::Query<LogFilters>,
) -> impl Responder {
    let limit = filters.limit.unwrap_or(100);
    let offset = filters.offset.unwrap_or(0);

    let mut query = String::from(
        r#"
        SELECT 
            l.id,
            l.id_tipo_accion,
            l.id_accion,
            l.id_usuario,
            l.accion,
            l.cedula_relacionada,
            l.ip_origen,
            l.user_agent,
            l.created_at,
            u.username,
            r.nombre_rol
        FROM logs l
        LEFT JOIN usuarios u ON l.id_usuario = u.id
        LEFT JOIN roles r ON u.id_rol = r.id
        WHERE 1=1
        "#
    );

    if let Some(id_usuario) = filters.id_usuario {
        query.push_str(&format!(" AND l.id_usuario = {}", id_usuario));
    }

    if let Some(id_tipo_accion) = filters.id_tipo_accion {
        query.push_str(&format!(" AND l.id_tipo_accion = {}", id_tipo_accion));
    }

    if let Some(id_accion) = filters.id_accion {
        query.push_str(&format!(" AND l.id_accion = {}", id_accion));
    }

    if let Some(cedula_relacionada) = filters.cedula_relacionada {
        query.push_str(&format!(" AND l.cedula_relacionada = {}", cedula_relacionada));
    }

    if let Some(fecha_desde) = &filters.fecha_desde {
        query.push_str(&format!(" AND l.created_at >= '{}'", fecha_desde));
    }

    if let Some(fecha_hasta) = &filters.fecha_hasta {
        query.push_str(&format!(" AND l.created_at <= '{}'", fecha_hasta));
    }

    // ✅ MEJORADO: Filtro por accion (MULTIPLE)
    if let Some(accion) = &filters.accion {
        let acciones: Vec<&str> = accion.split(',').collect();
        log::info!("🔍 Filtro acciones: {:?}", acciones);
        
        if acciones.len() == 1 {
            // Una sola acción
            let accion_escaped = acciones[0].replace('\'', "''");
            query.push_str(&format!(" AND l.accion = '{}'", accion_escaped));
            log::info!("🔍 Query con una acción: {}", accion_escaped);
        } else {
            // Múltiples acciones
            let acciones_str: Vec<String> = acciones
                .iter()
                .map(|a| {
                    let escaped = a.replace('\'', "''");
                    log::info!("🔍 Acción individual: {} -> {}", a, escaped);
                    format!("'{}'", escaped)
                })
                .collect();
            let in_clause = acciones_str.join(",");
            log::info!("🔍 IN clause: {}", in_clause);
            query.push_str(&format!(" AND l.accion IN ({})", in_clause));
        }
    }

    query.push_str(&format!(" ORDER BY l.created_at DESC LIMIT {} OFFSET {}", limit, offset));

    log::info!("🔍 Query completo: {}", query);

    match sqlx::query_as::<_, LogEntryResponse>(&query)
        .fetch_all(&app_state.pool_pg)
        .await
    {
        Ok(logs) => {
            log::info!("✅ Logs encontrados: {}", logs.len());
            HttpResponse::Ok().json(logs)
        },
        Err(e) => {
            log::error!("❌ Error obteniendo logs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo logs",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn get_logs_resumen(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, LogResumen>(
        r#"
        SELECT 
            l.id_accion,
            a.accion,
            COUNT(*)::bigint as total
        FROM logs l
        JOIN acciones a ON l.id_accion = a.id AND l.id_tipo_accion = a.id_tipo_accion
        GROUP BY l.id_accion, a.accion
        ORDER BY total DESC
        "#
    )
    .fetch_all(&app_state.pool_pg)
    .await
    {
        Ok(resumen) => HttpResponse::Ok().json(resumen),
        Err(e) => {
            log::error!("❌ Error obteniendo resumen de logs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo resumen",
                "details": e.to_string()
            }))
        }
    }
}

// ============================================
// ✅ NUEVO: Obtener carga_masiva_id desde log_id
// ============================================

pub async fn get_carga_masiva_id_by_log(
    app_state: web::Data<AppState>,
    path: web::Path<i32>,
) -> impl Responder {
    let log_id = path.into_inner();
    
    log::info!("📥 Obteniendo carga_masiva_id para log_id: {}", log_id);
    
    match sqlx::query_scalar::<_, i32>(
        r#"SELECT id_accion FROM logs WHERE id = $1 AND accion = 'CARGA MASIVA DE USUARIOS'"#
    )
    .bind(log_id)
    .fetch_optional(&app_state.pool_pg)
    .await
    {
        Ok(Some(id)) => {
            log::info!("📊 carga_masiva_id encontrado: {}", id);
            HttpResponse::Ok().json(serde_json::json!({ 
                "carga_masiva_id": id 
            }))
        },
        Ok(None) => {
            log::warn!("⚠️ Log no encontrado o no es carga masiva: {}", log_id);
            HttpResponse::NotFound().json(serde_json::json!({ 
                "error": format!("Log {} no encontrado o no es carga masiva", log_id)
            }))
        }
        Err(e) => {
            log::error!("Error obteniendo carga_masiva_id: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ 
                "error": e.to_string() 
            }))
        }
    }
}