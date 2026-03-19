// src/modules/ac.rs
use actix_web::{web, HttpResponse, Error};
use oracle::Connection;
use serde::{Deserialize, Serialize};
use std::env;
use log::{info, error, warn};

// ✅ Función de conexión simplificada
fn oracle_conn() -> Result<Connection, oracle::Error> {
    let username = env::var("ORACLE_USER").expect("ORACLE_USER faltante");
    let password = env::var("ORACLE_PASS").expect("ORACLE_PASS faltante");
    let oracle_ip = env::var("ORACLE_IP").expect("ORACLE_IP faltante");
    let oracle_port = env::var("ORACLE_PORT").expect("ORACLE_PORT faltante");
    let oracle_db = env::var("ORACLE_DB").expect("ORACLE_DB faltante");
    
    let connect_string = format!("//{oracle_ip}:{oracle_port}/{oracle_db}");
    
    info!("🔗 Conectando a Oracle: {}@{}:{}/{}", username, oracle_ip, oracle_port, oracle_db);
    
    Connection::connect(username, password, connect_string)
}

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
    path: web::Path<(String, i64)>,
) -> Result<HttpResponse, Error> {
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

    // ✅ Conexión Oracle con logging
    let conn = match oracle_conn() {
        Ok(c) => {
            info!("✅ Conexión Oracle exitosa");
            c
        },
        Err(e) => {
            error!("❌ Error conectando a Oracle: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Error conectando a Oracle: {}", e),
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
        },
        Err(e) => {
            error!("❌ Error en query Oracle: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Error consultando Oracle: {}", e),
            }));
        }
    };

    // ✅ Lectura de fila
    let row_opt = match rows.next().transpose() {
        Ok(r) => r,
        Err(e) => {
            error!("❌ Error leyendo resultado: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Error leyendo datos: {}", e),
            }));
        }
    };

    let row = match row_opt {
        Some(r) => {
            info!("✅ Elector encontrado");
            r
        },
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