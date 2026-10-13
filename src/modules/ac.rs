use actix_web::{web, Error, HttpRequest, HttpResponse};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::middleware::auth::require_consulta_completa;
use crate::structs::AppState;

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct UsuarioAC {
    pub nacionalidad: String,
    pub cedula: i64,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub status_objecion: Option<i32>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn get_usuario_by_ac(
    req: HttpRequest,
    path: web::Path<(String, i64)>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(res) = require_consulta_completa(&req) {
        return Ok(res);
    }

    let (nacionalidad_raw, cedula) = path.into_inner();
    let nacionalidad = nacionalidad_raw.trim().to_uppercase();

    info!("🔍 Buscando elector: {} - {}", nacionalidad, cedula);

    // ✅ Validación
    if !(nacionalidad == "V" || nacionalidad == "E") {
        warn!("⚠️ Nacionalidad inválida: {}", nacionalidad);
        return Err(actix_web::error::ErrorBadRequest("nacionalidad debe ser V o E"));
    }

    if cedula <= 0 {
        warn!("⚠️ Cédula inválida: {}", cedula);
        return Err(actix_web::error::ErrorBadRequest("cedula debe ser mayor a 0"));
    }

    // ✅ Conexión Oracle desde el Pool (reutiliza conexión existente)
    let conn = match app_state.pool_oracle.get() {
        Ok(c) => c,
        Err(e) => {
            error!("❌ Error obteniendo conexión de Oracle Pool: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error interno del servidor".to_string(),
            }));
        }
    };

    let sql_persona = r#"
        SELECT 
          PRIMER_APELLIDO, 
          SEGUNDO_APELLIDO, 
          PRIMER_NOMBRE, 
          SEGUNDO_NOMBRE,
          STATUS_OBJECION
        FROM RE.AC
        WHERE NACIONALIDAD = :nacionalidad 
          AND CEDULA = :cedula
    "#;

    info!("📝 Ejecutando query");

    // ✅ Query con logging
    let mut rows = match conn.query(sql_persona, &[&nacionalidad, &cedula]) {
        Ok(r) => {
            info!("✅ Query ejecutado correctamente");
            r
        }
        Err(e) => {
            error!("❌ Error en query Oracle: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error interno del servidor".to_string(),
            }));
        }
    };

    // ✅ Lectura de fila
    let row_opt = match rows.next().transpose() {
        Ok(r) => r,
        Err(e) => {
            error!("❌ Error leyendo resultado: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error interno del servidor".to_string(),
            }));
        }
    };

    let row = match row_opt {
        Some(r) => {
            info!("✅ Elector encontrado");
            r
        }
        None => {
            warn!("⚠️ Elector no encontrado: {} - {}", nacionalidad, cedula);
            return Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "Elector no encontrado en RE.AC".to_string(),
            }));
        }
    };

    // ✅ Extraer datos
    let usuario = UsuarioAC {
        nacionalidad: nacionalidad.clone(),
        cedula,
        primer_apellido: row.get(0).ok(),
        segundo_apellido: row.get(1).ok(),
        primer_nombre: row.get(2).ok(),
        segundo_nombre: row.get(3).ok(),
        status_objecion: row.get(4).ok(),
    };

    info!("✅ Datos obtenidos: {:?}", usuario);

    Ok(HttpResponse::Ok().json(usuario))
}