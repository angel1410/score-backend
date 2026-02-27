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
    pub honeypot: Option<String>,           // 🍯 Honeypot
    pub captcha_id: Option<String>,         // 🧮 CAPTCHA ID
    pub captcha_answer: Option<String>,     // 🧮 CAPTCHA Respuesta
}

// ✅ Respuesta del CAPTCHA
#[derive(Serialize)]
pub struct CaptchaResponse {
    pub id: String,
    pub operation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    
    // ✅ Generar números aleatorios (1-10)
    let num1 = rng.gen_range(1..10);
    let num2 = rng.gen_range(1..10);
    let result = num1 + num2;
    
    // ✅ Generar ID único para el CAPTCHA
    let id: String = (0..16)
        .map(|_| rng.sample(&rand::distributions::Alphanumeric) as char)
        .collect();
    
    // ✅ Guardar respuesta en memoria (expira en 5 minutos)
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

    // 🍯 1. HONEYPOT - Si tiene valor, es bot
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

    // 🛡️ 2. RATE LIMITING - Verificar intentos por IP
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
                    // ✅ Resetear después de 15 minutos
                    attempts.remove(&client_ip);
                }
            }
        }
    }

    // 🧮 3. CAPTCHA MATEMÁTICO - Validar respuesta
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
                
                // ✅ Incrementar contador de intentos
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
            
            // ✅ Eliminar CAPTCHA usado (un solo uso)
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

    // ✅ 5. Consultar usuario en BD
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
            warn!("❌ Credenciales inválidas - Cédula: {}", cedula);
            
            // ✅ Incrementar contador de intentos fallidos
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

    // ✅ 6. Verificar usuario activo
    if login_data.activo != 1 {
        warn!("⚠️ Usuario inactivo - Cédula: {}", cedula);
        return HttpResponse::Forbidden().json(ErrorResponse {
            error: "Usuario inactivo. Contacte al administrador.".to_string(),
        });
    }

    // ✅ 7. Generar JWT Token
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

    // ✅ 8. Generar información de la hora del servidor
    let now_local = Local::now();
    let server_time = ServerTimeInfo {
        timestamp: now.timestamp(),
        timestamp_ms: now.timestamp_millis(),
        iso8601_utc: now.to_rfc3339(),
        iso8601_local: now_local.to_rfc3339(),
        timezone: now_local.format("%Z").to_string(),
    };

    // ✅ LOG antes de mover login_data
    info!("✅ Login exitoso - Usuario: {} ({})", login_data.nombre, cedula);

    let response = LoginResponse { 
        token, 
        user: login_data,
        server_time,
    };

    // ✅ Resetear intentos después de login exitoso
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        attempts.remove(&client_ip);
    }

    HttpResponse::Ok().json(response)
}