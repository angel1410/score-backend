// src/modules/users.rs
use actix_web::{web, HttpResponse, Responder, Error};
use actix_multipart::Multipart;
use sqlx::FromRow;
use sqlx::Row;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::PathBuf;
use log::info;
use csv::ReaderBuilder;
use calamine::{DataType as CalamineDataType, Reader, Xls, Xlsx};
use futures_util::TryStreamExt;
use sha2::{Sha256, Digest};
use log;
use crate::structs::AppState;

// ============================================
// ✅ ESTRUCTURAS
// ============================================

#[derive(FromRow, Serialize, Deserialize, Debug, Clone)]
pub struct Usuario {
    pub id: i32,
    pub id_rol: i32,
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
    pub username: String,
    pub password: String,
    pub activo: bool,
    pub expira: bool,
}

#[derive(FromRow, Serialize, Deserialize, Debug, Clone)]
pub struct UsuarioConRol {
    pub id: i32,
    pub id_rol: i32,
    pub nombre_rol: String,
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
    pub username: String,
    pub activo: bool,
    pub expira: bool,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioCreate {
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
    pub id_rol: i32,
    pub activo: bool,
    pub expira: bool,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioUpdate {
    pub password: Option<String>,
    pub activo: bool,
    pub expira: bool,
    pub id_rol: i32,
}

#[derive(Serialize)]
pub struct UsuarioConPassword {
    pub usuario: Usuario,
    pub password_generada: String,
}

// ✅ ESTRUCTURA PARA RESULTADO DE CARGA MASIVA (CON REACTIVADOS)
#[derive(Serialize)]
pub struct CargaMasivaResultado {
    pub exitosos: usize,
    pub fallidos: usize,
    pub reactivados: usize,
    pub detalles: Vec<String>,
    pub carga_masiva_id: Option<i32>,
}

// ✅ Respuesta de error (UNA SOLA VEZ)
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ============================================
// ✅ ESTRUCTURAS PARA VALIDACIÓN CON DISCREPANCIAS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACData {
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discrepancia {
    pub campo: String,
    pub valor_excel: String,
    pub valor_ac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilaPreview {
    pub fila: usize,
    pub nacionalidad: String,
    pub cedula: i32,
    pub estado: String,  // "VALIDO", "DISCREPANCIA", "INVALIDO", "RECHAZADO"
    pub excel_primer_nombre: String,
    pub excel_segundo_nombre: String,
    pub excel_primer_apellido: String,
    pub excel_segundo_apellido: String,
    pub ac_primer_nombre: Option<String>,
    pub ac_segundo_nombre: Option<String>,
    pub ac_primer_apellido: Option<String>,
    pub ac_segundo_apellido: Option<String>,
    pub discrepancias: Vec<Discrepancia>,
    pub mensaje_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargaMasivaPreview {
    pub total_filas: usize,
    pub validos_sin_discrepancia: usize,
    pub validos_con_discrepancia: usize,
    pub invalidos: usize,
    pub filas: Vec<FilaPreview>,
}

#[derive(Deserialize, Debug)]
pub struct ConfirmarCargaRequest {
    pub filas: Vec<FilaConfirmar>,
    pub archivo_nombre: String,
    pub archivo_tipo: String,
    pub archivo_tamano: usize,
}

#[derive(Deserialize, Debug)]
pub struct FilaConfirmar {
    pub fila: usize,
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
    pub id_rol: i32,
}

// ============================================
// ✅ ESTRUCTURAS PARA DESCARGAR EXCEL
// ============================================

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct CargaMasivaDetalle {
    pub id: i32,
    pub carga_masiva_id: i32,
    pub usuario_id: Option<i32>,
    pub cedula: i32,
    pub nacionalidad: String,
    pub nombre_completo: String,
    pub username: Option<String>,
    pub estado: String,
    pub error_detalle: Option<String>,
    pub created_at: chrono::NaiveDateTime,
}

// ============================================
// ✅ HELPERS
// ============================================

async fn obtener_id_usuario_del_token(
    req: &actix_web::HttpRequest,
    app_state: &AppState,
) -> Result<i32, String> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Claims {
        sub: String,
        exp: usize,
        iat: usize,
    }

    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        return Err("Token no encontrado".to_string());
    }

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(app_state.jwt_secret.as_bytes()),
        &Validation::default()
    ) {
        Ok(token_data) => {
            let user_id = token_data.claims.sub.parse::<i32>()
                .map_err(|_| "ID inválido en token")?;
            Ok(user_id)
        }
        Err(_) => Err("Token inválido".to_string())
    }
}

fn generar_username(primer_nombre: &str, primer_apellido: &str, _cedula: i32) -> String {
    let inicial_nombre = primer_nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();
    let apellido_limpio = primer_apellido.trim().to_lowercase();
    format!("{}{}", inicial_nombre, apellido_limpio)
}

fn generar_password(primer_nombre: &str, primer_apellido: &str, cedula: i32) -> String {
    let inicial_nombre = primer_nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();
    let inicial_apellido = primer_apellido
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();
    format!("{}{}{}", inicial_nombre, inicial_apellido, cedula)
}

// ============================================
// ✅ CONSULTAR AC CON DATOS COMPLETOS
// ============================================

async fn consultar_ac(nacionalidad: &str, cedula: i32) -> Result<Option<ACData>, String> {
    use oracle::Connection;
    use std::env;

    let username = env::var("ORACLE_USER").map_err(|e| format!("ORACLE_USER no configurado: {}", e))?;
    let password = env::var("ORACLE_PASS").map_err(|e| format!("ORACLE_PASS no configurado: {}", e))?;
    let oracle_ip = env::var("ORACLE_IP").map_err(|e| format!("ORACLE_IP no configurado: {}", e))?;
    let oracle_port = env::var("ORACLE_PORT").map_err(|e| format!("ORACLE_PORT no configurado: {}", e))?;
    let oracle_db = env::var("ORACLE_DB").map_err(|e| format!("ORACLE_DB no configurado: {}", e))?;

    log::info!("🔗 Oracle: {}@{}:{}/{}", username, oracle_ip, oracle_port, oracle_db);

    let connect_string = format!("//{}:{}/{}", oracle_ip, oracle_port, oracle_db);

    let conn = Connection::connect(&username, &password, &connect_string)
        .map_err(|e| {
            log::error!("❌ Error Oracle: {}", e);
            format!("Error conectando a Oracle: {}", e)
        })?;

    let sql = "SELECT NACIONALIDAD, CEDULA, PRIMER_NOMBRE, NVL(SEGUNDO_NOMBRE, '') as SEGUNDO_NOMBRE, 
                      PRIMER_APELLIDO, NVL(SEGUNDO_APELLIDO, '') as SEGUNDO_APELLIDO 
               FROM RE.AC 
               WHERE NACIONALIDAD = :nacionalidad AND CEDULA = :cedula";

    let mut cursor = conn.query(sql, &[&nacionalidad, &cedula])
        .map_err(|e| format!("Error query AC: {}", e))?;

    if let Some(row) = cursor.next().transpose().map_err(|e| format!("Error leyendo AC: {}", e))? {
        Ok(Some(ACData {
            nacionalidad: row.get(0).unwrap_or_else(|_| nacionalidad.to_string()),
            cedula: row.get(1).unwrap_or(cedula),
            primer_nombre: row.get(2).unwrap_or_default(),
            segundo_nombre: row.get(3).unwrap_or_default(),
            primer_apellido: row.get(4).unwrap_or_default(),
            segundo_apellido: row.get(5).unwrap_or_default(),
        }))
    } else {
        Ok(None)
    }
}

// ============================================
// ✅ COMPARAR DATOS EXCEL VS AC
// ============================================

fn comparar_datos(excel: &FilaPreview, ac: &ACData) -> Vec<Discrepancia> {
    let mut discrepancias = Vec::new();
    let normalize = |s: &str| -> String {
        s.to_uppercase()
            .replace('Á', "A").replace('É', "E").replace('Í', "I")
            .replace('Ó', "O").replace('Ú', "U").replace('Ñ', "N")
            .trim()
            .to_string()
    };

    if normalize(&excel.excel_primer_nombre) != normalize(&ac.primer_nombre) {
        discrepancias.push(Discrepancia {
            campo: "primer_nombre".to_string(),
            valor_excel: excel.excel_primer_nombre.clone(),
            valor_ac: ac.primer_nombre.clone(),
        });
    }
    if normalize(&excel.excel_segundo_nombre) != normalize(&ac.segundo_nombre) {
        discrepancias.push(Discrepancia {
            campo: "segundo_nombre".to_string(),
            valor_excel: excel.excel_segundo_nombre.clone(),
            valor_ac: ac.segundo_nombre.clone(),
        });
    }
    if normalize(&excel.excel_primer_apellido) != normalize(&ac.primer_apellido) {
        discrepancias.push(Discrepancia {
            campo: "primer_apellido".to_string(),
            valor_excel: excel.excel_primer_apellido.clone(),
            valor_ac: ac.primer_apellido.clone(),
        });
    }
    if normalize(&excel.excel_segundo_apellido) != normalize(&ac.segundo_apellido) {
        discrepancias.push(Discrepancia {
            campo: "segundo_apellido".to_string(),
            valor_excel: excel.excel_segundo_apellido.clone(),
            valor_ac: ac.segundo_apellido.clone(),
        });
    }
    discrepancias
}

// ============================================
// ✅ AUDITORÍA DE CARGA MASIVA
// ============================================

async fn registrar_carga_masiva_log(
    pool: &sqlx::PgPool,
    id_usuario: Option<i32>,
    archivo_nombre: &str,
    archivo_tipo: &str,
    archivo_size: usize,
    total_filas: usize,
    exitosos: usize,
    fallidos: usize,
    detalles: &str,
    ip_origen: &str,
    user_agent: &str,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO carga_masiva_logs
        (id_usuario, archivo_nombre, archivo_tipo, archivo_size, total_filas, exitosos, fallidos, detalles, ip_origen, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
        "#
    )
    .bind(&id_usuario)
    .bind(archivo_nombre)
    .bind(archivo_tipo)
    .bind(&(archivo_size as i32))
    .bind(&(total_filas as i32))
    .bind(&(exitosos as i32))
    .bind(&(fallidos as i32))
    .bind(detalles)
    .bind(ip_origen)
    .bind(user_agent)
    .fetch_one(pool)
    .await?;
    Ok(result)
}

async fn registrar_carga_masiva_detalle(
    pool: &sqlx::PgPool,
    carga_masiva_id: i32,
    usuario_id: Option<i32>,
    cedula: i32,
    nacionalidad: &str,
    nombre_completo: &str,
    username: Option<&str>,
    estado: &str,
    error_detalle: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO carga_masiva_detalles
        (carga_masiva_id, usuario_id, cedula, nacionalidad, nombre_completo, username, estado, error_detalle)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#
    )
    .bind(carga_masiva_id)
    .bind(&usuario_id)
    .bind(cedula)
    .bind(nacionalidad)
    .bind(nombre_completo)
    .bind(&username)
    .bind(estado)
    .bind(&error_detalle)
    .execute(pool)
    .await?;
    Ok(())
}

// ============================================
// ✅ CRUD USUARIOS
// ============================================

pub async fn get_usuarios(app_state: web::Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, UsuarioConRol>(
        "SELECT u.id, u.id_rol, COALESCE(r.nombre_rol, 'Sin Rol') AS nombre_rol,
                u.nacionalidad, u.cedula, u.primer_nombre, u.segundo_nombre,
                u.primer_apellido, u.segundo_apellido, u.username, u.activo, u.expira
         FROM usuarios u LEFT JOIN roles r ON u.id_rol = r.id
         WHERE u.eliminado = FALSE ORDER BY u.id DESC"
    )
    .fetch_all(&app_state.pool_pg)
    .await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => {
            log::error!("Error al obtener usuarios: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn get_roles(app_state: web::Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, (i32, String)>(
        "SELECT id, nombre_rol FROM roles ORDER BY id ASC"
    )
    .fetch_all(&app_state.pool_pg)
    .await {
        Ok(roles) => HttpResponse::Ok().json(roles),
        Err(e) => {
            log::error!("Error al obtener roles: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let nacionalidad = usuario.nacionalidad.trim().to_uppercase();
    let cedula = usuario.cedula;
    
    if !(nacionalidad == "V" || nacionalidad == "E") {
        return HttpResponse::BadRequest().body("nacionalidad debe ser V o E");
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return HttpResponse::BadRequest().body("cedula inválida");
    }

    let usuario_existente = sqlx::query(
        r#"SELECT id, eliminado FROM usuarios WHERE nacionalidad = $1 AND cedula = $2 LIMIT 1"#
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .fetch_optional(&app_state.pool_pg)
    .await;

    match usuario_existente {
        Ok(Some(row)) => {
            let eliminado: bool = row.get("eliminado");
            if eliminado {
                let usuario_id: i32 = row.get("id");
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "Usuario eliminado previamente",
                    "codigo": "USR_ELIMINADO",
                    "usuario_id": usuario_id,
                    "sugerencia": "Use el endpoint de reactivación para restaurar este usuario"
                }));
            } else {
                return HttpResponse::Conflict().body("Ya existe un usuario con esa cédula");
            }
        }
        Ok(None) => {}
        Err(e) => {
            log::error!("Error verificando duplicado: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    }

    let username = generar_username(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let password_generada = generar_password(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password_generada.as_bytes()));

    let user = match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, 
         segundo_apellido, username, password, activo, expira, id_rol, origen_creacion)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'MANUAL')
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
                   primer_apellido, segundo_apellido, username, password, activo, expira"
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .bind(&usuario.primer_nombre)
    .bind(&usuario.segundo_nombre)
    .bind(&usuario.primer_apellido)
    .bind(&usuario.segundo_apellido)
    .bind(&username)
    .bind(&hashed_password)
    .bind(usuario.activo)
    .bind(usuario.expira)
    .bind(usuario.id_rol)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Error al crear usuario: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    };

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    let log_entry = LogEntry {
        id_tipo_accion: 2,
        id_accion: 3,
        id_usuario: autor_id,
        accion: "CREAR USUARIO".to_string(),
        cedula_relacionada: Some(cedula),
        ip_origen,
        user_agent,
    };

    let pool_clone = app_state.pool_pg.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    HttpResponse::Created().json(UsuarioConPassword {
        usuario: user,
        password_generada,
    })
}

pub async fn reactivar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = TRUE"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado o no está eliminado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado o no está eliminado"
            }));
        }
    };

    let usuario_cedula = existing_user.cedula;

    match sqlx::query(
        r#"UPDATE usuarios SET eliminado = FALSE, eliminado_en = NULL, eliminado_por = NULL WHERE id = $1"#
    )
    .bind(user_id)
    .execute(&app_state.pool_pg)
    .await {
        Ok(_) => {
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);
            let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

            let log_entry = LogEntry {
                id_tipo_accion: 2,
                id_accion: 13,
                id_usuario: autor_id,
                accion: "REACTIVAR USUARIO".to_string(),
                cedula_relacionada: Some(usuario_cedula),
                ip_origen,
                user_agent,
            };

            let pool_clone = app_state.pool_pg.clone();
            tokio::spawn(async move {
                let _ = registrar_log(&pool_clone, log_entry).await;
            });

            HttpResponse::Ok().json(serde_json::json!({
                "message": "Usuario reactivado exitosamente",
                "usuario_id": user_id
            }))
        }
        Err(e) => {
            log::error!("Error reactivando usuario: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error reactivando usuario",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn actualizar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
    usuario: web::Json<UsuarioUpdate>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado"
            }));
        }
    };

    let password_to_use = match &usuario.password {
        Some(p) if !p.trim().is_empty() => format!("{:x}", Sha256::digest(p.as_bytes())),
        _ => existing_user.password,
    };

    let updated_user = match sqlx::query_as::<_, Usuario>(
        "UPDATE usuarios SET password = $1, activo = $2, expira = $3, id_rol = $4 
         WHERE id = $5 RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, 
         segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira"
    )
    .bind(&password_to_use)
    .bind(usuario.activo)
    .bind(usuario.expira)
    .bind(usuario.id_rol)
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Error al actualizar usuario: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error al actualizar usuario",
                "details": e.to_string()
            }));
        }
    };

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    let log_entry = LogEntry {
        id_tipo_accion: 2,
        id_accion: 4,
        id_usuario: autor_id,
        accion: "EDITAR USUARIO".to_string(),
        cedula_relacionada: Some(existing_user.cedula),
        ip_origen,
        user_agent,
    };

    let pool_clone = app_state.pool_pg.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    HttpResponse::Ok().json(updated_user)
}

pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado"
            }));
        }
    };

    let usuario_cedula = existing_user.cedula;
    let estado_actual = existing_user.activo;
    let (id_accion, accion_nombre) = if estado_actual {
        (6, "BLOQUEAR USUARIO")
    } else {
        (12, "DESBLOQUEAR USUARIO")
    };

    match sqlx::query_as::<_, Usuario>(
        "UPDATE usuarios SET activo = NOT activo WHERE id = $1 
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
                   primer_apellido, segundo_apellido, username, password, activo, expira"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(user) => {
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);
            let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

            let log_entry = LogEntry {
                id_tipo_accion: 2,
                id_accion,
                id_usuario: autor_id,
                accion: accion_nombre.to_string(),
                cedula_relacionada: Some(usuario_cedula),
                ip_origen,
                user_agent,
            };

            let pool_clone = app_state.pool_pg.clone();
            tokio::spawn(async move {
                let _ = registrar_log(&pool_clone, log_entry).await;
            });

            HttpResponse::Ok().json(user)
        }
        Err(e) => {
            log::error!("Error al bloquear/desbloquear usuario: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn eliminar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, 
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = FALSE"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado o ya eliminado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado o ya eliminado"
            }));
        }
    };

    let usuario_cedula = existing_user.cedula;
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    match sqlx::query(
        r#"UPDATE usuarios SET eliminado = TRUE, eliminado_en = CURRENT_TIMESTAMP, 
           eliminado_por = $2 WHERE id = $1"#
    )
    .bind(user_id)
    .bind(&autor_id)
    .execute(&app_state.pool_pg)
    .await {
        Ok(_) => {
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);

            let log_entry = LogEntry {
                id_tipo_accion: 2,
                id_accion: 5,
                id_usuario: autor_id,
                accion: "ELIMINAR USUARIO".to_string(),
                cedula_relacionada: Some(usuario_cedula),
                ip_origen,
                user_agent,
            };

            let pool_clone = app_state.pool_pg.clone();
            tokio::spawn(async move {
                let _ = registrar_log(&pool_clone, log_entry).await;
            });

            HttpResponse::Ok().body("Usuario eliminado")
        }
        Err(e) => {
            log::error!("Error eliminando usuario: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error eliminando usuario",
                "details": e.to_string()
            }))
        }
    }
}

// ============================================
// ✅ VALIDAR CARGA MASIVA (PREVIEW)
// ============================================

pub async fn validar_carga_masiva(
    app_state: web::Data<AppState>,
    _req: actix_web::HttpRequest,
    mut payload: Multipart,
) -> impl Responder {
    let mut file_buffer = Vec::new();
    let mut file_name = String::from("unknown");

    while let Ok(Some(mut field)) = payload.try_next().await {
        if let Some(content_disposition) = field.content_disposition() {
            if let Some(filename) = content_disposition.get_filename() {
                file_name = filename.to_string();
            }
        }
        while let Some(chunk) = field.try_next().await.unwrap_or(None) {
            file_buffer.extend_from_slice(&chunk);
        }
    }

    if file_buffer.is_empty() {
        return HttpResponse::BadRequest().body("No se recibió archivo");
    }

    let file_size = file_buffer.len();
    let _file_type = file_name.split('.').last().unwrap_or("unknown").to_lowercase();

    if file_size > 5_000_000 {
        return HttpResponse::BadRequest().body("Archivo excede 5MB");
    }

    let result = if file_name.ends_with(".csv") {
        validar_csv_preview(&file_buffer, app_state.clone()).await
    } else if file_name.ends_with(".xlsx") {
        validar_xlsx_preview(&file_buffer, app_state.clone()).await
    } else if file_name.ends_with(".xls") {
        validar_xls_preview(&file_buffer, app_state.clone()).await
    } else {
        return HttpResponse::BadRequest().body("Formato no soportado");
    };

    match result {
        Ok(preview) => HttpResponse::Ok().json(preview),
        Err(e) => {
            log::error!("Error validando carga masiva: {}", e);
            HttpResponse::InternalServerError().body(e)
        }
    }
}

// ============================================
// ✅ CONFIRMAR CARGA MASIVA (CON REACTIVACIÓN)
// ============================================

pub async fn confirmar_carga_masiva(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    body: web::Json<ConfirmarCargaRequest>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    let carga_masiva_id: Option<i32> = if let Some(uid) = autor_id {
        match registrar_carga_masiva_log(
            &app_state.pool_pg,
            Some(uid),
            &body.archivo_nombre,
            &body.archivo_tipo,
            body.archivo_tamano,
            body.filas.len(),
            0,
            0,
            "",
            &ip_origen,
            &user_agent,
        ).await {
            Ok(id) => Some(id),
            Err(e) => {
                log::error!("Error creando log de carga masiva: {}", e);
                None
            }
        }
    } else {
        None
    };

    let mut exitosos = 0;
    let mut fallidos = 0;
    let mut reactivados = 0;
    let mut detalles = Vec::new();

    for fila in body.filas.iter() {
        let nombre_completo = format!("{} {}", fila.primer_nombre, fila.primer_apellido);
        let username = generar_username(&fila.primer_nombre, &fila.primer_apellido, fila.cedula);
        let password = generar_password(&fila.primer_nombre, &fila.primer_apellido, fila.cedula);
        let hashed_password = format!("{:x}", Sha256::digest(password.as_bytes()));

        // ✅ 1. Verificar si existe por USERNAME (incluyendo eliminados)
        let usuario_existente = sqlx::query(
            "SELECT id, eliminado FROM usuarios WHERE username = $1"
        )
        .bind(&username)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match usuario_existente {
            Ok(Some(row)) => {
                let eliminado: bool = row.get("eliminado");
                let usuario_id: i32 = row.get("id");
                
                if eliminado {
                    // ✅ 2. Usuario eliminado → REACTIVAR Y ACTUALIZAR
                    match sqlx::query(
                        r#"UPDATE usuarios SET 
                           eliminado = FALSE, eliminado_en = NULL, eliminado_por = NULL,
                           nacionalidad = $1, cedula = $2, primer_nombre = $3, segundo_nombre = $4,
                           primer_apellido = $5, segundo_apellido = $6, password = $7,
                           activo = TRUE, expira = FALSE, id_rol = $8
                           WHERE id = $9"#
                    )
                    .bind(&fila.nacionalidad)
                    .bind(fila.cedula)
                    .bind(&fila.primer_nombre)
                    .bind(&fila.segundo_nombre)
                    .bind(&fila.primer_apellido)
                    .bind(&fila.segundo_apellido)
                    .bind(&hashed_password)
                    .bind(fila.id_rol)
                    .bind(usuario_id)
                    .execute(&app_state.pool_pg)
                    .await {
                        Ok(_) => {
                            exitosos += 1;
                            reactivados += 1;
                            detalles.push(format!("Fila {}: Usuario {} {} REACTIVADO (username: {})", 
                                fila.fila, fila.primer_nombre, fila.primer_apellido, username));
                            
                            if let Some(carga_id) = carga_masiva_id {
                                let _ = registrar_carga_masiva_detalle(
                                    &app_state.pool_pg, carga_id, Some(usuario_id), fila.cedula, &fila.nacionalidad,
                                    &nombre_completo, Some(&username), "REACTIVADO", None,
                                ).await;
                            }
                            
                            let log_entry = LogEntry {
                                id_tipo_accion: 2,
                                id_accion: 13,
                                id_usuario: autor_id,
                                accion: "REACTIVAR USUARIO".to_string(),
                                cedula_relacionada: Some(fila.cedula),
                                ip_origen: ip_origen.clone(),
                                user_agent: user_agent.clone(),
                            };
                            let pool_clone = app_state.pool_pg.clone();
                            tokio::spawn(async move {
                                let _ = registrar_log(&pool_clone, log_entry).await;
                            });
                        }
                        Err(e) => {
                            fallidos += 1;
                            detalles.push(format!("Fila {}: Error reactivando usuario: {}", fila.fila, e));
                        }
                    }
                    continue;
                } else {
                    fallidos += 1;
                    detalles.push(format!("Fila {}: Username '{}' ya existe (usuario activo)", fila.fila, username));
                    if let Some(carga_id) = carga_masiva_id {
                        let _ = registrar_carga_masiva_detalle(
                            &app_state.pool_pg, carga_id, None, fila.cedula, &fila.nacionalidad,
                            &nombre_completo, Some(&username), "FALLIDO", Some("Username duplicado (activo)"),
                        ).await;
                    }
                    continue;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error verificando usuario: {}", fila.fila, e));
                continue;
            }
        }

        // ✅ 3. Verificar duplicado por CEDULA (incluyendo eliminados)
        let cedula_existente = sqlx::query(
            "SELECT id, eliminado FROM usuarios WHERE nacionalidad = $1 AND cedula = $2"
        )
        .bind(&fila.nacionalidad)
        .bind(fila.cedula)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match cedula_existente {
            Ok(Some(row)) => {
                let eliminado: bool = row.get("eliminado");
                let usuario_id: i32 = row.get("id");
                
                if eliminado {
                    match sqlx::query(
                        r#"UPDATE usuarios SET 
                           eliminado = FALSE, eliminado_en = NULL, eliminado_por = NULL,
                           nacionalidad = $1, cedula = $2, primer_nombre = $3, segundo_nombre = $4,
                           primer_apellido = $5, segundo_apellido = $6, password = $7,
                           activo = TRUE, expira = FALSE, id_rol = $8, username = $9
                           WHERE id = $10"#
                    )
                    .bind(&fila.nacionalidad)
                    .bind(fila.cedula)
                    .bind(&fila.primer_nombre)
                    .bind(&fila.segundo_nombre)
                    .bind(&fila.primer_apellido)
                    .bind(&fila.segundo_apellido)
                    .bind(&hashed_password)
                    .bind(fila.id_rol)
                    .bind(&username)
                    .bind(usuario_id)
                    .execute(&app_state.pool_pg)
                    .await {
                        Ok(_) => {
                            exitosos += 1;
                            reactivados += 1;
                            detalles.push(format!("Fila {}: Usuario {} {} REACTIVADO por cédula (username: {})", 
                                fila.fila, fila.primer_nombre, fila.primer_apellido, username));
                            
                            if let Some(carga_id) = carga_masiva_id {
                                let _ = registrar_carga_masiva_detalle(
                                    &app_state.pool_pg, carga_id, Some(usuario_id), fila.cedula, &fila.nacionalidad,
                                    &nombre_completo, Some(&username), "REACTIVADO", None,
                                ).await;
                            }
                            
                            let log_entry = LogEntry {
                                id_tipo_accion: 2,
                                id_accion: 13,
                                id_usuario: autor_id,
                                accion: "REACTIVAR USUARIO".to_string(),
                                cedula_relacionada: Some(fila.cedula),
                                ip_origen: ip_origen.clone(),
                                user_agent: user_agent.clone(),
                            };
                            let pool_clone = app_state.pool_pg.clone();
                            tokio::spawn(async move {
                                let _ = registrar_log(&pool_clone, log_entry).await;
                            });
                        }
                        Err(e) => {
                            fallidos += 1;
                            detalles.push(format!("Fila {}: Error reactivando usuario por cédula: {}", fila.fila, e));
                        }
                    }
                    continue;
                } else {
                    fallidos += 1;
                    detalles.push(format!("Fila {}: Cédula {}-{} ya existe (usuario activo)", fila.fila, fila.nacionalidad, fila.cedula));
                    if let Some(carga_id) = carga_masiva_id {
                        let _ = registrar_carga_masiva_detalle(
                            &app_state.pool_pg, carga_id, None, fila.cedula, &fila.nacionalidad,
                            &nombre_completo, Some(&username), "FALLIDO", Some("Cédula duplicada (activa)"),
                        ).await;
                    }
                    continue;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error verificando cédula: {}", fila.fila, e));
                continue;
            }
        }

        // ✅ 4. Crear usuario nuevo
        let insert_result = sqlx::query(
            r#"INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, 
               primer_apellido, segundo_apellido, username, password, activo, expira, id_rol, origen_creacion)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'CARGA_MASIVA')
               RETURNING id"#
        )
        .bind(&fila.nacionalidad)
        .bind(fila.cedula)
        .bind(&fila.primer_nombre)
        .bind(&fila.segundo_nombre)
        .bind(&fila.primer_apellido)
        .bind(&fila.segundo_apellido)
        .bind(&username)
        .bind(&hashed_password)
        .bind(true)
        .bind(false)
        .bind(fila.id_rol)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match insert_result {
            Ok(Some(row)) => {
                let usuario_id: i32 = row.get(0);
                exitosos += 1;
                detalles.push(format!("Fila {}: Usuario {} {} creado (username: {})", 
                    fila.fila, fila.primer_nombre, fila.primer_apellido, username));
                if let Some(carga_id) = carga_masiva_id {
                    let _ = registrar_carga_masiva_detalle(
                        &app_state.pool_pg, carga_id, Some(usuario_id), fila.cedula, &fila.nacionalidad,
                        &nombre_completo, Some(&username), "EXITOSO", None,
                    ).await;
                }
            }
            Ok(None) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: No se pudo crear el usuario", fila.fila));
            }
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error creando usuario: {}", fila.fila, e));
            }
        }
    }

    if let Some(carga_id) = carga_masiva_id {
        let detalles_json = serde_json::to_string(&detalles).unwrap_or_default();
        let _ = sqlx::query(
            r#"UPDATE carga_masiva_logs SET total_filas = $1, exitosos = $2, fallidos = $3, detalles = $4 WHERE id = $5"#
        )
        .bind(&((exitosos + fallidos) as i32))
        .bind(&(exitosos as i32))
        .bind(&(fallidos as i32))
        .bind(&detalles_json)
        .bind(carga_id)
        .execute(&app_state.pool_pg)
        .await;
    }

    // ✅ AHORA (id_accion = 7 que SÍ existe en acciones)
      let log_entry = LogEntry {
        id_tipo_accion: 2,
        id_accion: 7,  // ← 7 = "CARGA MASIVA DE USUARIOS" en tabla acciones
        id_usuario: autor_id,
        accion: "CARGA MASIVA DE USUARIOS".to_string(),
        cedula_relacionada: carga_masiva_id,  // ← AQUÍ VA EL carga_masiva_id (14, 15, 16...)
        ip_origen: ip_origen.clone(),
        user_agent: user_agent.clone(),
    };

    let pool_clone = app_state.pool_pg.clone();
    tokio::spawn(async move {
        let _ = registrar_log(&pool_clone, log_entry).await;
    });

    HttpResponse::Ok().json(CargaMasivaResultado {
        exitosos,
        fallidos,
        reactivados,
        detalles,
        carga_masiva_id,
    })
}

// ============================================
// ✅ FUNCIONES DE VALIDACIÓN PREVIEW
// ============================================

async fn validar_csv_preview(buffer: &[u8], app_state: web::Data<AppState>) -> Result<CargaMasivaPreview, String> {
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(Cursor::new(buffer));
    let mut filas = Vec::new();
    let mut row_idx = 0;

    for result in reader.records() {
        row_idx += 1;
        if row_idx == 1 { continue; }

        let record = result.map_err(|e| format!("Error leyendo CSV línea {}: {}", row_idx, e))?;
        if record.len() < 6 {
            filas.push(FilaPreview {
                fila: row_idx,
                nacionalidad: "".to_string(),
                cedula: 0,
                estado: "INVALIDO".to_string(),
                excel_primer_nombre: "".to_string(),
                excel_segundo_nombre: "".to_string(),
                excel_primer_apellido: "".to_string(),
                excel_segundo_apellido: "".to_string(),
                ac_primer_nombre: None,
                ac_segundo_nombre: None,
                ac_primer_apellido: None,
                ac_segundo_apellido: None,
                discrepancias: vec![],
                mensaje_error: Some(format!("Columnas insuficientes (se esperan 6)")),
            });
            continue;
        }

        let nacionalidad = record.get(0).unwrap_or("").trim().to_uppercase();
        let cedula: i32 = record.get(1).unwrap_or("0").trim().parse().unwrap_or(0);
        let primer_nombre = record.get(2).unwrap_or("").trim().to_string();
        let segundo_nombre = record.get(3).unwrap_or("").trim().to_string();
        let primer_apellido = record.get(4).unwrap_or("").trim().to_string();
        let segundo_apellido = record.get(5).unwrap_or("").trim().to_string();

        let fila_preview = procesar_fila_preview(
            app_state.clone(),
            row_idx,
            nacionalidad,
            cedula,
            primer_nombre,
            segundo_nombre,
            primer_apellido,
            segundo_apellido,
        ).await;

        filas.push(fila_preview);
    }

    Ok(calcular_resumen_preview(filas))
}

async fn validar_xlsx_preview(buffer: &[u8], app_state: web::Data<AppState>) -> Result<CargaMasivaPreview, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xlsx::new(cursor).map_err(|e| format!("Error abriendo XLSX: {}", e))?;
    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLSX".to_string());
    }
    let range = workbook.worksheet_range(&sheet_names[0]).map_err(|e| format!("Error leyendo hoja: {}", e))?;
    validar_range_preview(range, app_state).await
}

async fn validar_xls_preview(buffer: &[u8], app_state: web::Data<AppState>) -> Result<CargaMasivaPreview, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xls::new(cursor).map_err(|e| format!("Error abriendo XLS: {}", e))?;
    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLS".to_string());
    }
    let range = workbook.worksheet_range(&sheet_names[0]).map_err(|e| format!("Error leyendo hoja: {}", e))?;
    validar_range_preview(range, app_state).await
}

async fn validar_range_preview(range: calamine::Range<CalamineDataType>, app_state: web::Data<AppState>) -> Result<CargaMasivaPreview, String> {
    let mut filas = Vec::new();
    let mut row_idx = 0;

    for row in range.rows() {
        row_idx += 1;
        if row_idx == 1 { continue; }
        if row.len() < 6 {
            filas.push(FilaPreview {
                fila: row_idx,
                nacionalidad: "".to_string(),
                cedula: 0,
                estado: "INVALIDO".to_string(),
                excel_primer_nombre: "".to_string(),
                excel_segundo_nombre: "".to_string(),
                excel_primer_apellido: "".to_string(),
                excel_segundo_apellido: "".to_string(),
                ac_primer_nombre: None,
                ac_segundo_nombre: None,
                ac_primer_apellido: None,
                ac_segundo_apellido: None,
                discrepancias: vec![],
                mensaje_error: Some(format!("Columnas insuficientes (se esperan 6)")),
            });
            continue;
        }

        let nacionalidad = match &row[0] {
            CalamineDataType::String(s) => s.trim().to_uppercase(),
            _ => "".to_string(),
        };

        let cedula = match &row[1] {
            CalamineDataType::Float(f) => *f as i32,
            CalamineDataType::String(s) => s.trim().parse().unwrap_or(0),
            _ => 0,
        };

        let primer_nombre = match &row[2] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let segundo_nombre = match &row[3] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let primer_apellido = match &row[4] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let segundo_apellido = match &row[5] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let fila_preview = procesar_fila_preview(
            app_state.clone(),
            row_idx,
            nacionalidad,
            cedula,
            primer_nombre,
            segundo_nombre,
            primer_apellido,
            segundo_apellido,
        ).await;

        filas.push(fila_preview);
    }

    Ok(calcular_resumen_preview(filas))
}

async fn procesar_fila_preview(
    _app_state: web::Data<AppState>,
    fila: usize,
    nacionalidad: String,
    cedula: i32,
    excel_primer_nombre: String,
    excel_segundo_nombre: String,
    excel_primer_apellido: String,
    excel_segundo_apellido: String,
) -> FilaPreview {
    if nacionalidad.is_empty() || cedula == 0 || excel_primer_nombre.is_empty() || excel_primer_apellido.is_empty() {
        return FilaPreview {
            fila,
            nacionalidad,
            cedula,
            estado: "INVALIDO".to_string(),
            excel_primer_nombre,
            excel_segundo_nombre,
            excel_primer_apellido,
            excel_segundo_apellido,
            ac_primer_nombre: None,
            ac_segundo_nombre: None,
            ac_primer_apellido: None,
            ac_segundo_apellido: None,
            discrepancias: vec![],
            mensaje_error: Some("Datos incompletos".to_string()),
        };
    }

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return FilaPreview {
            fila,
            nacionalidad,
            cedula,
            estado: "INVALIDO".to_string(),
            excel_primer_nombre,
            excel_segundo_nombre,
            excel_primer_apellido,
            excel_segundo_apellido,
            ac_primer_nombre: None,
            ac_segundo_nombre: None,
            ac_primer_apellido: None,
            ac_segundo_apellido: None,
            discrepancias: vec![],
            mensaje_error: Some("Nacionalidad inválida (debe ser V o E)".to_string()),
        };
    }

    match consultar_ac(&nacionalidad, cedula).await {
        Ok(Some(ac_data)) => {
            let mut fila_preview = FilaPreview {
                fila,
                nacionalidad,
                cedula,
                estado: "VALIDO".to_string(),
                excel_primer_nombre,
                excel_segundo_nombre,
                excel_primer_apellido,
                excel_segundo_apellido,
                ac_primer_nombre: Some(ac_data.primer_nombre.clone()),
                ac_segundo_nombre: Some(ac_data.segundo_nombre.clone()),
                ac_primer_apellido: Some(ac_data.primer_apellido.clone()),
                ac_segundo_apellido: Some(ac_data.segundo_apellido.clone()),
                discrepancias: vec![],
                mensaje_error: None,
            };

            let discrepancias = comparar_datos(&fila_preview, &ac_data);
            
            if !discrepancias.is_empty() {
                fila_preview.estado = "DISCREPANCIA".to_string();
                fila_preview.discrepancias = discrepancias;
            }

            fila_preview
        }
        Ok(None) => FilaPreview {
            fila,
            nacionalidad,
            cedula,
            estado: "INVALIDO".to_string(),
            excel_primer_nombre,
            excel_segundo_nombre,
            excel_primer_apellido,
            excel_segundo_apellido,
            ac_primer_nombre: None,
            ac_segundo_nombre: None,
            ac_primer_apellido: None,
            ac_segundo_apellido: None,
            discrepancias: vec![],
            mensaje_error: Some("Cédula no existe en AC".to_string()),
        },
        Err(e) => FilaPreview {
            fila,
            nacionalidad,
            cedula,
            estado: "INVALIDO".to_string(),
            excel_primer_nombre,
            excel_segundo_nombre,
            excel_primer_apellido,
            excel_segundo_apellido,
            ac_primer_nombre: None,
            ac_segundo_nombre: None,
            ac_primer_apellido: None,
            ac_segundo_apellido: None,
            discrepancias: vec![],
            mensaje_error: Some(format!("Error consultando AC: {}", e)),
        },
    }
}

fn calcular_resumen_preview(filas: Vec<FilaPreview>) -> CargaMasivaPreview {
    let total_filas = filas.len();
    let validos_sin_discrepancia = filas.iter().filter(|f| f.estado == "VALIDO").count();
    let validos_con_discrepancia = filas.iter().filter(|f| f.estado == "DISCREPANCIA").count();
    let invalidos = filas.iter().filter(|f| f.estado == "INVALIDO").count();

    CargaMasivaPreview {
        total_filas,
        validos_sin_discrepancia,
        validos_con_discrepancia,
        invalidos,
        filas,
    }
}

// ============================================
// ✅ DESCARGAR PLANTILLA
// ============================================

pub async fn descargar_plantilla() -> Result<HttpResponse, Error> {
    info!("📥 Sirviendo plantilla Excel");
    let file_path = PathBuf::from("files/templates/plantilla.xlsx");
    if !file_path.exists() {
        return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Plantilla no encontrada en el servidor".to_string(),
        }));
    }
    let file_bytes = std::fs::read(&file_path).map_err(|e| {
        actix_web::error::ErrorInternalServerError(e)
    })?;
    info!("✅ Plantilla enviada: {} bytes", file_bytes.len());
    Ok(HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header(("Content-Disposition", "attachment; filename=\"plantilla_usuarios.xlsx\""))
        .body(file_bytes))
}

// ============================================
// ✅ DESCARGAR EXCEL DE CARGA MASIVA
// ============================================

pub async fn descargar_carga_masiva_excel(
    app_state: web::Data<AppState>,
    path: web::Path<i32>,
) -> impl Responder {
    let carga_masiva_id = path.into_inner();

    log::info!("📥 Descargando Excel para carga_masiva_id: {}", carga_masiva_id);

    // ✅ 1. Obtener detalles de la carga masiva
    let detalles = match sqlx::query_as::<_, CargaMasivaDetalle>(
        r#"
        SELECT id, carga_masiva_id, usuario_id, cedula, nacionalidad, 
               nombre_completo, username, estado, error_detalle, created_at
        FROM carga_masiva_detalles
        WHERE carga_masiva_id = $1
        ORDER BY id ASC
        "#
    )
    .bind(carga_masiva_id)
    .fetch_all(&app_state.pool_pg)
    .await
    {
        Ok(d) => d,
        Err(e) => {
            log::error!("Error obteniendo detalles: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo detalles de carga masiva",
                "details": e.to_string()
            }));
        }
    };

    log::info!("📊 Detalles encontrados: {} registros", detalles.len());
    log::info!("📊 Exitosos: {}", detalles.iter().filter(|d| d.estado == "EXITOSO" || d.estado == "REACTIVADO").count());
    log::info!("📊 Fallidos: {}", detalles.iter().filter(|d| d.estado == "FALLIDO" || d.estado == "INVALIDO" || d.estado == "RECHAZADO").count());

    if detalles.is_empty() {
        log::warn!("⚠️ No se encontraron detalles para carga_masiva_id: {}", carga_masiva_id);
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("No se encontraron detalles para carga_masiva_id {}", carga_masiva_id)
        }));
    }

    // ✅ 2. Generar Excel con rust_xlsxwriter
    use rust_xlsxwriter::{Workbook, Format, FormatAlign, FormatBorder};

    let mut workbook = Workbook::new();
    
    let header_format = Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_border(FormatBorder::Thin)
        .set_background_color(rust_xlsxwriter::Color::Green);

    let normal_format = Format::new();

    // Hoja 1: Exitosos
    let sheet = workbook.add_worksheet().set_name("Exitosos").unwrap();
    
    let headers = ["Nacionalidad", "Cédula", "Nombre Completo", "Username", "Estado"];
    for (col, header) in headers.iter().enumerate() {
        sheet.write_string_with_format(0, col as u16, *header, &header_format).unwrap();
    }

    let mut row = 1;
    for detalle in &detalles {
        if detalle.estado == "EXITOSO" || detalle.estado == "REACTIVADO" {
            sheet.write_string_with_format(row, 0, &detalle.nacionalidad, &normal_format).unwrap();
            sheet.write_number_with_format(row, 1, detalle.cedula as f64, &normal_format).unwrap();
            sheet.write_string_with_format(row, 2, &detalle.nombre_completo, &normal_format).unwrap();
            sheet.write_string_with_format(row, 3, detalle.username.as_deref().unwrap_or(""), &normal_format).unwrap();
            sheet.write_string_with_format(row, 4, &detalle.estado, &normal_format).unwrap();
            row += 1;
        }
    }

    // Hoja 2: Fallidos
    let sheet = workbook.add_worksheet().set_name("Fallidos").unwrap();
    
    let headers = ["Nacionalidad", "Cédula", "Nombre Completo", "Username", "Estado", "Error"];
    for (col, header) in headers.iter().enumerate() {
        sheet.write_string_with_format(0, col as u16, *header, &header_format).unwrap();
    }

    let mut row = 1;
    for detalle in &detalles {
        if detalle.estado == "FALLIDO" || detalle.estado == "INVALIDO" || detalle.estado == "RECHAZADO" {
            sheet.write_string_with_format(row, 0, &detalle.nacionalidad, &normal_format).unwrap();
            sheet.write_number_with_format(row, 1, detalle.cedula as f64, &normal_format).unwrap();
            sheet.write_string_with_format(row, 2, &detalle.nombre_completo, &normal_format).unwrap();
            sheet.write_string_with_format(row, 3, detalle.username.as_deref().unwrap_or(""), &normal_format).unwrap();
            sheet.write_string_with_format(row, 4, &detalle.estado, &normal_format).unwrap();
            sheet.write_string_with_format(row, 5, detalle.error_detalle.as_deref().unwrap_or(""), &normal_format).unwrap();
            row += 1;
        }
    }

    // ✅ 3. Guardar en buffer
    let buffer = match workbook.save_to_buffer() {
        Ok(buf) => buf,
        Err(e) => {
            log::error!("Error guardando Excel: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error generando archivo Excel",
                "details": e.to_string()
            }));
        }
    };

    // ✅ 4. Retornar archivo
    let nombre_archivo = format!("carga_masiva_{}_{}.xlsx", carga_masiva_id, chrono::Local::now().format("%Y%m%d_%H%M%S"));

    log::info!("✅ Excel generado: {}", nombre_archivo);

    HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", nombre_archivo)))
        .body(buffer)
}