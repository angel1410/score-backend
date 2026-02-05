use crate::structs;
use actix_web::{web, HttpResponse};
use chrono::{Duration, Utc, Local}; // ✅ Importar Local
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use log::error;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub struct InfoLogin {
    pub cedula: i32,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DatosLogin {
    id: i32,
    nacionalidad: String,
    cedula: i32,
    nombre: String,
    apellido: String,
    login: String,
    activo: i32,
    expired: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

// ✅ Nueva estructura para la hora del servidor
#[derive(Serialize)]
struct ServerTimeInfo {
    timestamp: i64,
    timestamp_ms: i64,
    iso8601_utc: String,
    iso8601_local: String,
    timezone: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: DatosLogin,
    server_time: ServerTimeInfo, // ✅ Agregar hora del servidor
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn get_login(
    state: web::Data<structs::AppState>,
    info: web::Json<InfoLogin>,
) -> HttpResponse {
    let cedula = info.cedula;
    let password = &info.password;
    let pool = &state.pool_pg;

    // ✅ Calcular SHA256 del password ingresado (formato hexadecimal)
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(password);
        format!("{:x}", hasher.finalize())
    };

    // ✅ Comparar directamente con VARCHAR (sin decode)
    let row_query = sqlx::query(
        "SELECT id, nacionalidad, cedula, nombre, apellido, login, activo, expired
         FROM usuario
         WHERE cedula = $1 AND password = $2;",
    )
    .bind(cedula)
    .bind(&sha256_hash)
    .fetch_optional(pool)
    .await;

    let row_query = match row_query {
        Ok(r) => r,
        Err(e) => {
            error!("Error BD: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error interno del servidor".to_string(),
            });
        }
    };

    let login_data = match row_query {
        Some(row) => DatosLogin {
            id: row.get(0),
            nacionalidad: row.get(1),
            cedula: row.get(2),
            nombre: row.get(3),
            apellido: row.get(4),
            login: row.get(5),
            activo: row.get(6),
            expired: row.get(7),
        },
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Credenciales inválidas".to_string(),
            });
        }
    };

    let now = Utc::now();
    let expiration = match now.checked_add_signed(Duration::hours(4)) {
        Some(exp) => exp.timestamp(),
        None => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error calculando expiración".to_string(),
            });
        }
    };

    let claims = Claims {
        sub: login_data.id.to_string(),
        exp: expiration as usize,
        iat: now.timestamp() as usize,
    };

    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes())) {
        Ok(t) => t,
        Err(e) => {
            error!("Error creando token: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error generando token".to_string(),
            });
        }
    };

    // ✅ Generar información de la hora del servidor
    let now_local = Local::now();
    let server_time = ServerTimeInfo {
        timestamp: now.timestamp(),
        timestamp_ms: now.timestamp_millis(),
        iso8601_utc: now.to_rfc3339(),
        iso8601_local: now_local.to_rfc3339(),
        timezone: now_local.format("%Z").to_string(),
    };

    let response = LoginResponse { 
        token, 
        user: login_data,
        server_time, // ✅ Incluir en la respuesta
    };

    HttpResponse::Ok().json(response)
}