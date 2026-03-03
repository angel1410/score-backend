// src/modules/login.rs
use crate::structs;
use actix_web::{web, HttpResponse};
use chrono::{Duration, Utc, Local};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use log::{error, warn, info};
use sha2::{Digest, Sha256};
use rand::Rng;

// ✅ Estructura de entrada con las 3 protecciones
#[derive(Deserialize)]
pub struct InfoLogin {
    pub cedula: i32,
    pub password: String,
    pub honeypot: Option<String>,
    pub captcha_id: Option<String>,
    pub captcha_answer: Option<String>,
}

// ✅ Respuesta del CAPTCHA
#[derive(Serialize)]
pub struct CaptchaResponse {
    pub id: String,
    pub operation: String,
}

// ✅ Estructura actualizada CON id_rol y nombre_rol
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DatosLogin {
    id: i32,
    id_rol: i32,              // ✅ ID del rol
    nombre_rol: String,       // ✅ NUEVO: Nombre del rol
    nacionalidad: String,
    cedula: i32,
    primer_nombre: String,
    segundo_nombre: String,
    primer_apellido: String,
    segundo_apellido: String,
    username: String,
    activo: bool,
    expira: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

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
    server_time: ServerTimeInfo,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ✅ Endpoint para generar CAPTCHA matemático
pub async fn get_captcha(
    state: web::Data<structs::AppState>,
) -> HttpResponse {
    let mut rng = rand::thread_rng();
    
    let num1 = rng.gen_range(1..10);
    let num2 = rng.gen_range(1..10);
    let result = num1 + num2;
    
    let id: String = (0..16)
        .map(|_| rng.sample(&rand::distributions::Alphanumeric) as char)
        .collect();
    
    {
        let mut store = state.captcha_store.lock().unwrap();
        store.insert(id.clone(), result.to_string());
    }
    
    info!("🧮 CAPTCHA generado: {} + {} = ?", num1, num2);
    
    HttpResponse::Ok().json(CaptchaResponse {
        id,
        operation: format!("{} + {} = ?", num1, num2),
    })
}

// ✅ Endpoint de login con las 3 protecciones
pub async fn get_login(
    state: web::Data<structs::AppState>,
    info: web::Json<InfoLogin>,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    let cedula = info.cedula;
    let password = &info.password;
    let pool = &state.pool_pg;

    // 🍯 1. HONEYPOT
    if let Some(honeypot_value) = &info.honeypot {
        if !honeypot_value.is_empty() {
            let client_ip = req
                .headers()
                .get("X-Forwarded-For")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown");
            
            warn!("🤖 BOT DETECTADO (Honeypot) - IP: {}, Cédula: {}", client_ip, cedula);
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Solicitud inválida".to_string(),
            });
        }
    }

    // 🛡️ 2. RATE LIMITING
    let client_ip = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        
        if let Some(tracker) = attempts.get(&client_ip) {
            if tracker.count >= 5 {
                let elapsed = Utc::now() - tracker.last_attempt;
                if elapsed < Duration::minutes(15) {
                    warn!("🚫 RATE LIMIT EXCEDIDO - IP: {}, Intentos: {}", client_ip, tracker.count);
                    return HttpResponse::TooManyRequests().json(ErrorResponse {
                        error: "Demasiados intentos. Espera 15 minutos.".to_string(),
                    });
                } else {
                    attempts.remove(&client_ip);
                }
            }
        }
    }

    // 🧮 3. CAPTCHA MATEMÁTICO
    if let Some(captcha_id) = &info.captcha_id {
        if let Some(captcha_answer) = &info.captcha_answer {
            let valid = {
                let store = state.captcha_store.lock().unwrap();
                if let Some(expected) = store.get(captcha_id) {
                    expected == captcha_answer
                } else {
                    false
                }
            };
            
            if !valid {
                warn!("❌ CAPTCHA incorrecto - Cédula: {}", cedula);
                
                {
                    let mut attempts = state.login_attempts.lock().unwrap();
                    let tracker = attempts.entry(client_ip.clone()).or_insert(structs::AttemptTracker {
                        count: 0,
                        last_attempt: Utc::now(),
                    });
                    tracker.count += 1;
                    tracker.last_attempt = Utc::now();
                }
                
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "CAPTCHA incorrecto. Intente de nuevo.".to_string(),
                });
            }
            
            {
                let mut store = state.captcha_store.lock().unwrap();
                store.remove(captcha_id);
            }
        } else {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "CAPTCHA requerido".to_string(),
            });
        }
    } else {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "CAPTCHA requerido".to_string(),
        });
    }

    // ✅ 4. Calcular SHA256 del password
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(password);
        format!("{:x}", hasher.finalize())
    };

    // ✅ 5. Consultar usuario en BD (12 columnas CON JOIN a rol)
    let row_query = sqlx::query(
        "SELECT u.id, u.id_rol, r.nombre_rol, u.nacionalidad, u.cedula, 
                u.primer_nombre, u.segundo_nombre, u.primer_apellido, u.segundo_apellido, 
                u.username, u.activo, u.expira
         FROM usuarios u
         LEFT JOIN roles r ON u.id_rol = r.id
         WHERE u.cedula = $1 AND u.password = $2;",
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

    // ✅ 6. Mapear row a struct (12 columnas, índices 0-11)
    let login_data = match row_query {
        Some(row) => DatosLogin {
            id: row.get(0),               // id
            id_rol: row.get(1),           // id_rol
            nombre_rol: row.get(2),       // ✅ nombre_rol (del JOIN)
            nacionalidad: row.get(3),     // nacionalidad
            cedula: row.get(4),           // cedula
            primer_nombre: row.get(5),    // primer_nombre
            segundo_nombre: row.get(6),   // segundo_nombre
            primer_apellido: row.get(7),  // primer_apellido
            segundo_apellido: row.get(8), // segundo_apellido
            username: row.get(9),         // username
            activo: row.get(10),          // activo (bool)
            expira: row.get(11),          // expira (bool)
        },
        None => {
            warn!("❌ Credenciales inválidas - Cédula: {}", cedula);
            
            {
                let mut attempts = state.login_attempts.lock().unwrap();
                let tracker = attempts.entry(client_ip.clone()).or_insert(structs::AttemptTracker {
                    count: 0,
                    last_attempt: Utc::now(),
                });
                tracker.count += 1;
                tracker.last_attempt = Utc::now();
            }
            
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Credenciales inválidas".to_string(),
            });
        }
    };

    // ✅ 7. Verificar usuario activo (bool)
    if !login_data.activo {
        warn!("⚠️ Usuario inactivo - Cédula: {}", cedula);
        return HttpResponse::Forbidden().json(ErrorResponse {
            error: "Usuario inactivo. Contacte al administrador.".to_string(),
        });
    }

    // ✅ 8. Generar JWT Token
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

    // ✅ 9. Generar información de la hora del servidor
    let now_local = Local::now();
    let server_time = ServerTimeInfo {
        timestamp: now.timestamp(),
        timestamp_ms: now.timestamp_millis(),
        iso8601_utc: now.to_rfc3339(),
        iso8601_local: now_local.to_rfc3339(),
        timezone: now_local.format("%Z").to_string(),
    };

    // ✅ 10. Log con nombre completo, rol ID y nombre del rol
    let nombre_completo = [
        login_data.primer_nombre.as_str(),
        login_data.segundo_nombre.as_str()
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" ");

    info!("✅ Login exitoso - Usuario: {} ({}) - Rol: {} ({})", nombre_completo, cedula, login_data.id_rol, login_data.nombre_rol);

    let response = LoginResponse { 
        token, 
        user: login_data,
        server_time,
    };

    // ✅ 11. Resetear intentos después de login exitoso
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        attempts.remove(&client_ip);
    }

    HttpResponse::Ok().json(response)
}