use actix_web::{web, HttpResponse, Error};
use oracle::Connection;
use serde::{Deserialize, Serialize};
use std::env;

fn oracle_conn() -> Result<Connection, oracle::Error> {
    let username = env::var("ORACLE_USER").unwrap();
    let password = env::var("ORACLE_PASS").unwrap();
    let oracle_ip = env::var("ORACLE_IP").unwrap();
    let oracle_port = env::var("ORACLE_PORT").unwrap();
    let oracle_db = env::var("ORACLE_DB").unwrap();
    let connect_string = format!("//{oracle_ip}:{oracle_port}/{oracle_db}");
    Connection::connect(username, password, connect_string)
}

#[derive(Deserialize, Serialize, Default)]
pub struct UsuarioAC {
    pub nacionalidad: String,
    pub cedula: i64,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
}

pub async fn get_usuario_by_ac(
    path: web::Path<(String, i64)>,
) -> Result<HttpResponse, Error> {
    let (nacionalidad_raw, cedula) = path.into_inner();
    let nacionalidad = nacionalidad_raw.trim().to_uppercase();
    
    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nacionalidad debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let conn = oracle_conn()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e)))?;

    let sql_persona = r#"
        SELECT 
          PRIMER_APELLIDO, 
          SEGUNDO_APELLIDO, 
          PRIMER_NOMBRE, 
          SEGUNDO_NOMBRE 
        FROM RE.AC
        WHERE NACIONALIDAD = :nacionalidad 
          AND CEDULA = :cedula
    "#;

    let mut rows = conn.query(sql_persona, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query AC: {}", e)))?;

    let row_opt = rows.next().transpose()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo AC: {}", e)))?;

    let row = match row_opt {
        Some(r) => r,
        None => {
            // ✅ CORREGIDO: Usar body() en lugar de json() con sintaxis inválida
            return Ok(HttpResponse::NotFound().body("Elector no encontrado"));
        }
    };

    let usuario = UsuarioAC {
        nacionalidad,
        cedula,
        primer_apellido: row.get(0).ok(),
        segundo_apellido: row.get(1).ok(),
        primer_nombre: row.get(2).ok(),
        segundo_nombre: row.get(3).ok(),
    };

    Ok(HttpResponse::Ok().json(usuario))
}