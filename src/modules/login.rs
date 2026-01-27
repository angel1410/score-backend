use crate::structs;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use ntex::web::{Error, HttpResponse, Responder, error, types};
use serde::{Deserialize, Serialize};
use sqlx::Row;

// 1. Estructura para recibir los datos del POST (Body)
#[derive(Deserialize)]
pub struct InfoLogin {
  pub cedula: i32,
  pub password: String,
}

// Estructura de usuario (BD)
#[derive(Serialize, Deserialize, Debug)]
struct DatosLogin {
  id: i32,
  nacionalidad: String,
  cedula: i32,
  nombre: String,
  apellido: String,
  activo: i32,
  expired: i32,
}

// Claims para JWT
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  sub: String,
  exp: usize,
  iat: usize,
}

// Respuesta final
#[derive(Serialize)]
struct LoginResponse {
  token: String,
  user: DatosLogin,
}

pub async fn get_login(state: types::State<structs::AppState>, info: types::Json<InfoLogin>) -> Result<impl Responder, Error> {
  let cedula = info.cedula;
  let password = &info.password; // Referencia al string del json

  let pool = &state.pool_pg;

  let row_query = sqlx::query(
    "SELECT id, nacionalidad, cedula, nombre, apellido, activo, expired
            FROM usuario
            WHERE cedula = $1 AND password = SHA256($2::bytea)::text;",
  )
  .bind(cedula)
  .bind(password)
  .fetch_optional(pool)
  .await
  .map_err(|e| {
    log::error!("Error BD: {}", e);
    error::ErrorInternalServerError("Error interno")
  })?;

  let login_data = match row_query {
    Some(row) => DatosLogin {
      id: row.get(0),
      nacionalidad: row.get(1),
      cedula: row.get(2),
      nombre: row.get(3),
      apellido: row.get(4),
      activo: row.get(5),
      expired: row.get(6),
    },
    None => return Err(error::ErrorUnauthorized("Credenciales inválidas").into()),
  };

  // 1. Calcular expiración: Ahora + 4 horas
  let now = Utc::now();
  let expiration = now.checked_add_signed(Duration::hours(4)).expect("Timestamp válido").timestamp();

  // 2. Crear los claims
  let claims = Claims {
    sub: login_data.id.to_string(), // Usamos el ID como subject
    exp: expiration as usize,
    iat: now.timestamp() as usize,
  };

  // 3. Firmar el token usando el secreto del AppState
  let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes())).map_err(|e| {
    log::error!("Error creando token: {}", e);
    error::ErrorInternalServerError("Error generando autenticación")
  })?;

  // 4. Crear respuesta combinada
  let response = LoginResponse { token, user: login_data };

  // Imprimir debug (opcional, cuidado en producción)
  // println!("{:?}", response.user);

  Ok(HttpResponse::Ok().json(&response))
}
