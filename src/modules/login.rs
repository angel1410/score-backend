use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};
use crate::structs;
use crate::utils::security_monitor;
use actix_web::{web, HttpResponse};
use chrono::{Duration, Local, NaiveDate, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

// ✅ Roles del sistema
const ROL_ADMINISTRADOR: i32 = 1;
const ROL_SISTEMAS: i32 = 4;

// ✅ Roles que pueden iniciar sesión aunque la fecha_cierre esté vencida
fn puede_ingresar_fuera_de_fecha(id_rol: i32) -> bool {
    matches!(id_rol, ROL_ADMINISTRADOR | ROL_SISTEMAS)
}

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
    id_rol: i32,
    nombre_rol: String,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    role: String,
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
pub async fn get_captcha(state: web::Data<structs::AppState>) -> HttpResponse {
    let mut rng = rand::thread_rng();

    let operations = ['+', '-'];
    let op = operations[rng.gen_range(0..operations.len())];

    let num1: i32 = rng.gen_range(1..15);
    let num2: i32 = rng.gen_range(1..15);

    let result: i32 = match op {
        '+' => num1 + num2,
        '-' => num1.saturating_sub(num2),
        _ => num1 + num2,
    };

    let id: String = (0..32)
        .map(|_| rng.sample(&rand::distributions::Alphanumeric) as char)
        .collect();

    {
        let mut store = state.captcha_store.lock().unwrap();
        store.insert(
            id.clone(),
            structs::CaptchaEntry {
                answer: result.to_string(),
                created_at: Utc::now(),
            },
        );
    }

    info!("🧮 CAPTCHA generado");

    HttpResponse::Ok().json(CaptchaResponse {
        id,
        operation: format!("{} {} {} = ?", num1, op, num2),
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
            let client_ip = extract_ip(&req);

            let log_entry = LogEntry {
                id_tipo_accion: 4,
                id_accion: 15,
                id_usuario: None,
                accion: "HONEYPOT ACTIVADO".to_string(),
                cedula_relacionada: Some(cedula),
                ip_origen: client_ip.clone(),
                user_agent: extract_user_agent(&req),
            };

            let pool_clone = pool.clone();
            tokio::spawn(async move {
                let _ = registrar_log(&pool_clone, log_entry).await;
            });

            security_monitor::alert_honeypot(&client_ip, Some(cedula));

            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Solicitud inválida".to_string(),
            });
        }
    }

    // 🛡️ 2. RATE LIMITING
    let client_ip = extract_ip(&req);

    {
        let mut attempts = state.login_attempts.lock().unwrap();

        if let Some(tracker) = attempts.get(&client_ip) {
            if tracker.count >= 5 {
                let elapsed = Utc::now() - tracker.last_attempt;
                if elapsed < Duration::minutes(15) {
                    let log_entry = LogEntry {
                        id_tipo_accion: 4,
                        id_accion: 17,
                        id_usuario: None,
                        accion: "RATE LIMIT EXCEDIDO".to_string(),
                        cedula_relacionada: None,
                        ip_origen: client_ip.clone(),
                        user_agent: extract_user_agent(&req),
                    };

                    let pool_clone = pool.clone();
                    tokio::spawn(async move {
                        let _ = registrar_log(&pool_clone, log_entry).await;
                    });

                    security_monitor::alert_rate_limit(&client_ip, tracker.count);

                    return HttpResponse::TooManyRequests().json(ErrorResponse {
                        error: "Demasiados intentos. Espera 15 minutos.".to_string(),
                    });
                } else {
                    attempts.remove(&client_ip);
                }
            }
        }
    }

    // 🧮 3. CAPTCHA
    if let Some(captcha_id) = &info.captcha_id {
        if let Some(captcha_answer) = &info.captcha_answer {
            let valid = {
                let mut store = state.captcha_store.lock().unwrap();

                if let Some(entry) = store.get(captcha_id) {
                    let elapsed = Utc::now() - entry.created_at;

                    if elapsed > chrono::Duration::minutes(5) {
                        store.remove(captcha_id);
                        false
                    } else {
                        entry.answer == *captcha_answer
                    }
                } else {
                    false
                }
            };

            if !valid {
                let log_entry = LogEntry {
                    id_tipo_accion: 4,
                    id_accion: 16,
                    id_usuario: None,
                    accion: "CAPTCHA INVÁLIDO".to_string(),
                    cedula_relacionada: Some(cedula),
                    ip_origen: client_ip.clone(),
                    user_agent: extract_user_agent(&req),
                };

                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    let _ = registrar_log(&pool_clone, log_entry).await;
                });

                security_monitor::alert_invalid_captcha(&client_ip, Some(cedula));

                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "CAPTCHA incorrecto o expirado. Intente de nuevo.".to_string(),
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

    // ✅ 5. Consultar usuario
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

    let login_data = match row_query {
        Some(row) => DatosLogin {
            id: row.get(0),
            id_rol: row.get(1),
            nombre_rol: row.get::<Option<String>, _>(2).unwrap_or_else(|| "SIN_ROL".to_string()),
            nacionalidad: row.get(3),
            cedula: row.get(4),
            primer_nombre: row.get(5),
            segundo_nombre: row.get(6),
            primer_apellido: row.get(7),
            segundo_apellido: row.get(8),
            username: row.get(9),
            activo: row.get(10),
            expira: row.get(11),
        },
        None => {
            warn!("❌ Credenciales inválidas - Cédula: {}", cedula);

            {
                let mut attempts = state.login_attempts.lock().unwrap();
                let tracker = attempts
                    .entry(client_ip.clone())
                    .or_insert(structs::AttemptTracker {
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

    if !login_data.activo {
        warn!("⚠️ Usuario inactivo - Cédula: {}", cedula);
        return HttpResponse::Forbidden().json(ErrorResponse {
            error: "Usuario inactivo. Contacte al administrador.".to_string(),
        });
    }

    // ✅ 6. Validar fecha_cierre solo para roles que NO están exentos
    //
    // Roles exentos:
    // - 1 ADMINISTRADOR
    // - 4 SISTEMAS
    //
    // Roles sujetos a fecha_cierre:
// - 2 DIRECTOR
// - 3 OPERADOR
    if !puede_ingresar_fuera_de_fecha(login_data.id_rol) {
        let fecha_cierre_result = sqlx::query_scalar::<_, Option<NaiveDate>>(
            "SELECT p_date FROM parametros WHERE nombre_parametro = 'fecha_cierre'",
        )
        .fetch_optional(pool)
        .await;

        let fecha_cierre: Option<NaiveDate> = match fecha_cierre_result {
            Ok(Some(fecha)) => fecha,
            Ok(None) => None,
            Err(e) => {
                error!("Error consultando fecha_cierre: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Error validando fecha de cierre".to_string(),
                });
            }
        };

        if let Some(fecha) = fecha_cierre {
            let hoy = Local::now().naive_local().date();

            if hoy > fecha {
                warn!(
                    "⚠️ Fecha de cierre vencida - Cédula: {}, Rol: {}, Fecha cierre: {}, Hoy: {}",
                    cedula, login_data.id_rol, fecha, hoy
                );

                return HttpResponse::Forbidden().json(ErrorResponse {
                    error: "Acceso denegado. La fecha límite para inicio de sesión ha vencido."
                        .to_string(),
                });
            }
        }
    } else {
        info!(
            "✅ Usuario exento de fecha_cierre - Cédula: {}, Rol: {} ({})",
            cedula, login_data.id_rol, login_data.nombre_rol
        );
    }

    // ✅ 7. Generar JWT Token con role
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
        role: login_data.id_rol.to_string(),
        exp: expiration as usize,
        iat: now.timestamp() as usize,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("Error creando token: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Error generando token".to_string(),
            });
        }
    };

    let now_local = Local::now();
    let server_time = ServerTimeInfo {
        timestamp: now.timestamp(),
        timestamp_ms: now.timestamp_millis(),
        iso8601_utc: now.to_rfc3339(),
        iso8601_local: now_local.to_rfc3339(),
        timezone: now_local.format("%Z").to_string(),
    };

    let nombre_completo = [login_data.primer_nombre.as_str(), login_data.segundo_nombre.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    info!(
        "✅ Login exitoso - Usuario: {} ({}) - Rol: {} ({})",
        nombre_completo, cedula, login_data.id_rol, login_data.nombre_rol
    );

    let usuario_id = login_data.id;
    let usuario_cedula = login_data.cedula;

    let response = LoginResponse {
        token,
        user: login_data,
        server_time,
    };

    {
        let mut attempts = state.login_attempts.lock().unwrap();
        attempts.remove(&client_ip);
    }

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);

    let log_entry = LogEntry {
        id_tipo_accion: 1,
        id_accion: 1,
        id_usuario: Some(usuario_id),
        accion: "INICIO DE SESIÓN".to_string(),
        cedula_relacionada: Some(usuario_cedula),
        ip_origen,
        user_agent,
    };

    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    HttpResponse::Ok().json(response)
}

// ✅ Endpoint de logout con logging
pub async fn get_logout(
    state: web::Data<structs::AppState>,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    let usuario_id = if !token.is_empty() {
        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(token_data) => token_data.claims.sub.parse::<i32>().unwrap_or(0),
            Err(_) => 0,
        }
    } else {
        0
    };

    let usuario_cedula = if usuario_id > 0 {
        match sqlx::query_scalar::<_, i32>("SELECT cedula FROM usuarios WHERE id = $1")
            .bind(usuario_id)
            .fetch_optional(&state.pool_pg)
            .await
        {
            Ok(Some(cedula)) => Some(cedula),
            _ => None,
        }
    } else {
        None
    };

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);

    let log_entry = LogEntry {
        id_tipo_accion: 1,
        id_accion: 2,
        id_usuario: Some(usuario_id),
        accion: "CIERRE DE SESIÓN".to_string(),
        cedula_relacionada: usuario_cedula,
        ip_origen,
        user_agent,
    };

    let pool_clone = state.pool_pg.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Sesión cerrada exitosamente"
    }))
}