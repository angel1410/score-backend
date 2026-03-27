// src/modules/exportacion.rs
use actix_web::{web, HttpResponse, Responder, HttpRequest};
use serde::{Deserialize, Serialize};
use chrono::{Local, TimeZone, FixedOffset};
use crate::structs::AppState;
use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};

// ✅ Request para exportación
#[derive(Deserialize)]
pub struct ExportRequest {
    pub cedula: i32,
    #[allow(dead_code)]  // ✅ Para uso futuro
    pub secciones: Vec<String>,
    pub usuario_id: Option<i32>,
    #[allow(dead_code)]  // ✅ Para uso futuro
    pub fecha_generacion: Option<String>,
}

// ✅ Response de exportación
#[derive(Serialize)]
pub struct ExportResponse {
    pub valido: bool,
    pub mensaje: String,
    pub codigo_verificacion: String,
    pub cedula: i32,
    pub timestamp: i64,
}

// ✅ Endpoint para registrar exportación de reporte
pub async fn registrar_exportacion(
    state: web::Data<AppState>,
    req: HttpRequest,
    info: web::Json<ExportRequest>,
) -> impl Responder {
    let client_ip = extract_ip(&req);
    let user_agent = extract_user_agent(&req);

    // ✅ Validar datos mínimos
    if info.cedula <= 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cédula inválida"
        }));
    }

    // ✅ Logging de la solicitud (evita warnings de campos no usados)
    log::info!(
        "📄 Exportación: Cédula={}, Secciones={:?}, Usuario={:?}",
        info.cedula,
        info.secciones.len(),
        info.usuario_id
    );

    // ✅ Generar código de verificación único
    let tz = FixedOffset::west_opt(4 * 3600).unwrap();
    let ahora_utc = chrono::Utc::now();
    let timestamp = ahora_utc.timestamp();
    let fecha_formateada = ahora_utc
        .with_timezone(&tz)
        .format("%d/%m/%Y, %I:%M:%S %p")
        .to_string();

    let codigo_verificacion = format!("RE-{}-{}", timestamp, info.cedula);

    // ✅ Registrar log de exportación (usar id_accion=9 que ya existe)
    let log_entry = LogEntry {
        id_tipo_accion: 3,  // CONSULTAS
        id_accion: 9,        // EXPORTAR PDF
        id_usuario: info.usuario_id,
        accion: "EXPORTAR PDF".to_string(),
        cedula_relacionada: Some(info.cedula),
        ip_origen: client_ip,
        user_agent,
    };

    // ✅ Insertar log de forma asíncrona (no bloqueante)
    let pool_clone = state.pool_pg.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    // ✅ Responder con código de verificación
    HttpResponse::Ok().json(ExportResponse {
        valido: true,
        mensaje: "Exportación registrada exitosamente".to_string(),
        codigo_verificacion,
        cedula: info.cedula,
        timestamp,
    })
}

// ✅ Endpoint para verificar documento por código QR
pub async fn verificar_documento(
    state: web::Data<AppState>,
    codigo: web::Path<String>,
) -> impl Responder {
    // ✅ Validar formato: RE-TIMESTAMP-CEDULA
    let partes: Vec<&str> = codigo.split('-').collect();
    if partes.len() < 3 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "valido": false,
            "mensaje": "Código de verificación inválido",
            "codigo": codigo.to_string()
        }));
    }

    // Extraer cédula del código (última parte)
    let cedula = partes[partes.len() - 1];
    let timestamp_str = partes[1];
    let timestamp: Option<i64> = timestamp_str.parse().ok();

    // ✅ Buscar en logs si existe esta exportación
    let existe = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) as count,
            MAX(created_at) as ultima_exportacion
        FROM logs
        WHERE cedula_relacionada::text = $1
            AND id_tipo_accion = 3
            AND id_accion = 9
        "#,
        cedula
    )
    .fetch_optional(&state.pool_pg)
    .await;

    match existe {
        Ok(Some(row)) if row.count.unwrap_or(0) > 0 => {
            HttpResponse::Ok().json(serde_json::json!({
                "valido": true,
                "mensaje": "Documento verificado correctamente",
                "codigo": codigo.to_string(),
                "cedula": cedula,
                "timestamp":timestamp,
                "ultima_exportacion": row.ultima_exportacion
            }))
        },
        _ => HttpResponse::NotFound().json(serde_json::json!({
            "valido": false,
            "mensaje": "Documento no encontrado o inválido",
            "codigo": codigo.to_string()
        })),
    }
}