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

// ✅ Estructura Usuario para operaciones CRUD
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

// ✅ NUEVA: Estructura para respuesta con nombre_rol (solo lectura)
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

// ✅ Estructura para crear usuario
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

// ✅ Estructura para actualizar usuario
#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioUpdate {
    pub password: Option<String>,
    pub activo: bool,
    pub expira: bool,
    pub id_rol: i32,
}

// ✅ Respuesta con password generada
#[derive(Serialize)]
pub struct UsuarioConPassword {
    pub usuario: Usuario,
    pub password_generada: String,
}

// ✅ Resultado de carga masiva (ACTUALIZADO)
#[derive(Serialize)]
pub struct CargaMasivaResultado {
    pub exitosos: usize,
    pub fallidos: usize,
    pub detalles: Vec<String>,
    pub carga_masiva_id: Option<i32>,  // ✅ AGREGADO
}

// ✅ Respuesta de error
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ✅ Helper para obtener id_usuario del token JWT
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

// ✅ Generar username: inicial nombre + primer apellido
fn generar_username(primer_nombre: &str, primer_apellido: &str, _cedula: i32) -> String {
    let inicial_nombre = primer_nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();

    let apellido_limpio = primer_apellido.trim().to_lowercase();

    format!("{}{}", inicial_nombre, apellido_limpio)
}

// ✅ Generar password: inicial nombre + inicial apellido + cédula
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

// ✅ VALIDACIÓN: verificar si existe usuario por nacionalidad+cedula
async fn existe_usuario_por_cedula(
    app_state: &AppState,
    nacionalidad: &str,
    cedula: i32,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT 1
        FROM usuarios
        WHERE nacionalidad = $1 AND cedula = $2
        LIMIT 1
        "#
    )
    .bind(nacionalidad)
    .bind(cedula)
    .fetch_optional(&app_state.pool_pg)
    .await?
    .is_some();

    Ok(exists)
}

// ============================================
// ✅ NUEVAS FUNCIONES PARA AUDITORÍA DE CARGA MASIVA
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
// ✅ LISTAR todos los usuarios CON nombre_rol
// ============================================
pub async fn get_usuarios(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, UsuarioConRol>(
        "SELECT 
            u.id,
            u.id_rol,
            COALESCE(r.nombre_rol, 'Sin Rol') AS nombre_rol,
            u.nacionalidad, 
            u.cedula, 
            u.primer_nombre,
            u.segundo_nombre,
            u.primer_apellido,
            u.segundo_apellido,
            u.username,
            u.activo, 
            u.expira
         FROM usuarios u
         LEFT JOIN roles r ON u.id_rol = r.id
         WHERE u.eliminado = FALSE
         ORDER BY u.id DESC"
    )
    .fetch_all(&app_state.pool_pg)
    .await
    {
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

// ✅ LISTAR roles
pub async fn get_roles(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, (i32, String)>(
        "SELECT id, nombre_rol FROM roles ORDER BY id ASC"
    )
    .fetch_all(&app_state.pool_pg)
    .await
    {
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

// ✅ CREAR usuario nuevo CON VERIFICACIÓN DE ELIMINADOS
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

    // ✅ 1. Verificar si existe (incluyendo eliminados)
    let usuario_existente = sqlx::query(
        r#"
        SELECT id, eliminado FROM usuarios 
        WHERE nacionalidad = $1 AND cedula = $2
        LIMIT 1
        "#
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .fetch_optional(&app_state.pool_pg)
    .await;

    match usuario_existente {
        Ok(Some(row)) => {
            let eliminado: bool = row.get("eliminado");
            
            if eliminado {
                // ✅ 2. Si está eliminado, retornar error especial con ID
                let usuario_id: i32 = row.get("id");
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "Usuario eliminado previamente",
                    "codigo": "USR_ELIMINADO",
                    "usuario_id": usuario_id,
                    "sugerencia": "Use el endpoint de reactivación para restaurar este usuario"
                }));
            } else {
                // ✅ 3. Si existe y NO está eliminado → Error de duplicado normal
                return HttpResponse::Conflict().body("Ya existe un usuario con esa cédula");
            }
        }
        Ok(None) => {}  // ✅ No existe, continuar con creación
        Err(e) => {
            log::error!("Error verificando duplicado: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    }

    // ✅ 4. Continuar con creación normal...
    let username = generar_username(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let password_generada = generar_password(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password_generada.as_bytes()));

    let user = match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira, id_rol, origen_creacion) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'MANUAL') 
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira"
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
    .await
    {
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

// ✅ REACTIVAR usuario eliminado
pub async fn reactivar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    // ✅ 1. Verificar que existe y está eliminado
    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = TRUE"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado o no está eliminado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado o no está eliminado"
            }));
        }
    };

    let usuario_cedula = existing_user.cedula;

    // ✅ 2. Reactivar (soft delete reverso)
    match sqlx::query(
        r#"
        UPDATE usuarios 
        SET eliminado = FALSE, 
            eliminado_en = NULL, 
            eliminado_por = NULL
        WHERE id = $1
        "#
    )
    .bind(user_id)
    .execute(&app_state.pool_pg)
    .await
    {
        Ok(_) => {
            // ✅ 3. REGISTRAR LOG DE REACTIVACIÓN
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);
            let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

            let log_entry = LogEntry {
                id_tipo_accion: 2,
                id_accion: 13,  // REACTIVAR USUARIO
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

// ✅ ACTUALIZAR usuario existente CON LOGGING
pub async fn actualizar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
    usuario: web::Json<UsuarioUpdate>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
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
        "UPDATE usuarios SET password = $1, activo = $2, expira = $3, id_rol = $4 WHERE id = $5 
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira"
    )
    .bind(&password_to_use)
    .bind(usuario.activo)
    .bind(usuario.expira)
    .bind(usuario.id_rol)
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
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

// ✅ BLOQUEAR/DES BLOQUEAR usuario (toggle) CON LOGGING MEJORADO
pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
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
        "UPDATE usuarios SET activo = NOT activo
         WHERE id = $1 
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
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

// ✅ ELIMINAR usuario CON SOFT DELETE
pub async fn eliminar_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
    let user_id = id.into_inner();

    // ✅ 1. Obtener usuario ACTUAL
    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = FALSE"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("Usuario no encontrado o ya eliminado: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado o ya eliminado"
            }));
        }
    };

    let usuario_cedula = existing_user.cedula;

    // ✅ 2. Obtener autor_id para registrar quién elimina
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    // ✅ 3. SOFT DELETE (UPDATE, NO DELETE FÍSICO)
    match sqlx::query(
        r#"
        UPDATE usuarios 
        SET eliminado = TRUE, 
            eliminado_en = CURRENT_TIMESTAMP, 
            eliminado_por = $2
        WHERE id = $1
        "#
    )
    .bind(user_id)
    .bind(&autor_id)
    .execute(&app_state.pool_pg)
    .await
    {
        Ok(_) => {
            // ✅ 4. REGISTRAR LOG
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

            HttpResponse::Ok().body("Usuario eliminado")  // ✅ Soft delete exitoso
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

// ====== VALIDACIÓN CONTRA TABLA AC DE ORACLE ======
async fn validar_contra_ac(nacionalidad: &str, cedula: i32) -> Result<bool, String> {
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

    let sql = "SELECT 1 FROM RE.AC WHERE NACIONALIDAD = :nacionalidad AND CEDULA = :cedula";

    let exists = conn
        .query_row_as::<i32>(sql, &[&nacionalidad, &cedula])
        .ok()
        .is_some();

    Ok(exists)
}

// ====== CARGA MASIVA CON AUDITORÍA COMPLETA ======
pub async fn carga_masiva(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    mut payload: Multipart,
) -> impl Responder {
    use crate::modules::logging::{LogEntry, registrar_log, extract_ip, extract_user_agent};
    
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
    let file_type = file_name.split('.').last().unwrap_or("unknown").to_lowercase();

    if file_size > 5_000_000 {
        return HttpResponse::BadRequest().body("Archivo excede 5MB");
    }

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);
    let autor_id = obtener_id_usuario_del_token(&req, &app_state).await.ok();

    // ✅ 1. Crear registro en carga_masiva_logs PRIMERO
    let carga_masiva_id: Option<i32> = if let Some(uid) = autor_id {
        match registrar_carga_masiva_log(
            &app_state.pool_pg,
            Some(uid),
            &file_name,
            &file_type,
            file_size,
            0,
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

    // ✅ 2. Procesar archivo
    let result = if file_name.ends_with(".csv") {
        process_csv(&file_buffer, app_state.clone(), carga_masiva_id).await
    } else if file_name.ends_with(".xlsx") {
        process_excel_xlsx(&file_buffer, app_state.clone(), carga_masiva_id).await
    } else if file_name.ends_with(".xls") {
        process_excel_xls(&file_buffer, app_state.clone(), carga_masiva_id).await
    } else {
        return HttpResponse::BadRequest().body("Formato no soportado");
    };

    match result {
        Ok(res) => {
            let log_entry = LogEntry {
                id_tipo_accion: 2,
                id_accion: 7,
                id_usuario: autor_id,
                accion: "CARGA MASIVA DE USUARIOS".to_string(),
                cedula_relacionada: None,
                ip_origen: ip_origen.clone(),
                user_agent: user_agent.clone(),
            };

            let pool_clone = app_state.pool_pg.clone();
            let exitosos = res.exitosos;
            let fallidos = res.fallidos;
            let detalles_json = serde_json::to_string(&res.detalles).unwrap_or_default();
            let total_filas = exitosos + fallidos;
            
            tokio::spawn(async move {
                let _ = registrar_log(&pool_clone, log_entry).await;
                
                // ✅ 3. Actualizar carga_masiva_logs con resultados finales
                if let Some(carga_id) = carga_masiva_id {
                    let _ = sqlx::query(
                        r#"
                        UPDATE carga_masiva_logs 
                        SET total_filas = $1, exitosos = $2, fallidos = $3, detalles = $4
                        WHERE id = $5
                        "#
                    )
                    .bind(&(total_filas as i32))
                    .bind(&(exitosos as i32))
                    .bind(&(fallidos as i32))
                    .bind(&detalles_json)
                    .bind(carga_id)
                    .execute(&pool_clone)
                    .await;
                    
                    log::info!("📊 Carga masiva registrada con ID: {} | {} exitosos, {} fallidos", carga_id, exitosos, fallidos);
                }
            });

            HttpResponse::Ok().json(CargaMasivaResultado {
                exitosos: res.exitosos,
                fallidos: res.fallidos,
                detalles: res.detalles,
                carga_masiva_id,
            })
        }
        Err(e) => {
            log::error!("Error en carga masiva: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error procesando archivo",
                "details": e
            }))
        }
    }
}

// ✅ Procesar CSV
async fn process_csv(
    buffer: &[u8],
    app_state: web::Data<AppState>,
    carga_masiva_id: Option<i32>,
) -> Result<CargaMasivaResultado, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(Cursor::new(buffer));

    let mut exitosos = 0;
    let mut fallidos = 0;
    let mut detalles = Vec::new();

    for (idx, result) in reader.records().enumerate() {
        let record = result.map_err(|e| format!("Error leyendo CSV línea {}: {}", idx + 2, e))?;

        if record.len() < 6 {
            fallidos += 1;
            detalles.push(format!("Línea {}: Columnas insuficientes (se esperan 6)", idx + 2));
            continue;
        }

        let nacionalidad = record.get(0).unwrap_or("").trim().to_uppercase();
        let cedula: i32 = record.get(1).unwrap_or("0").trim().parse().unwrap_or(0);
        let primer_nombre = record.get(2).unwrap_or("").trim().to_string();
        let segundo_nombre = record.get(3).unwrap_or("").trim().to_string();
        let primer_apellido = record.get(4).unwrap_or("").trim().to_string();
        let segundo_apellido = record.get(5).unwrap_or("").trim().to_string();

        let id_rol = 3;
        let activo = true;
        let expira = false;

        procesar_fila(
            app_state.clone(),
            idx + 2,
            nacionalidad,
            cedula,
            primer_nombre,
            segundo_nombre,
            primer_apellido,
            segundo_apellido,
            id_rol,
            activo,
            expira,
            &mut exitosos,
            &mut fallidos,
            &mut detalles,
            carga_masiva_id,
            &app_state.pool_pg,
        ).await;
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles, carga_masiva_id })
}

// ✅ Procesar Excel XLSX
async fn process_excel_xlsx(
    buffer: &[u8],
    app_state: web::Data<AppState>,
    carga_masiva_id: Option<i32>,
) -> Result<CargaMasivaResultado, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xlsx::new(cursor)
        .map_err(|e| format!("Error abriendo archivo XLSX: {}", e))?;

    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLSX".to_string());
    }

    let range = workbook
        .worksheet_range(&sheet_names[0])
        .map_err(|e| format!("Error al leer hoja XLSX: {}", e))?;

    process_excel_range(range, app_state, carga_masiva_id).await
}

// ✅ Procesar Excel XLS
async fn process_excel_xls(
    buffer: &[u8],
    app_state: web::Data<AppState>,
    carga_masiva_id: Option<i32>,
) -> Result<CargaMasivaResultado, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xls::new(cursor)
        .map_err(|e| format!("Error abriendo archivo XLS: {}", e))?;

    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLS".to_string());
    }

    let range = workbook
        .worksheet_range(&sheet_names[0])
        .map_err(|e| format!("Error al leer hoja XLS: {}", e))?;

    process_excel_range(range, app_state, carga_masiva_id).await
}

// ✅ Procesar rango de Excel
async fn process_excel_range(
    range: calamine::Range<CalamineDataType>,
    app_state: web::Data<AppState>,
    carga_masiva_id: Option<i32>,
) -> Result<CargaMasivaResultado, String> {
    let mut exitosos = 0;
    let mut fallidos = 0;
    let mut detalles = Vec::new();
    let mut row_idx = 0;

    for row in range.rows() {
        if row_idx == 0 {
            row_idx += 1;
            continue;
        }

        if row.len() < 6 {
            fallidos += 1;
            detalles.push(format!("Fila {}: Columnas insuficientes (se esperan 6)", row_idx + 1));
            row_idx += 1;
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

        let id_rol = 3;  // ✅ OPERADOR
        let activo = true;
        let expira = false;

        procesar_fila(
            app_state.clone(),
            row_idx + 1,
            nacionalidad,
            cedula,
            primer_nombre,
            segundo_nombre,
            primer_apellido,
            segundo_apellido,
            id_rol,
            activo,
            expira,
            &mut exitosos,
            &mut fallidos,
            &mut detalles,
            carga_masiva_id,
            &app_state.pool_pg,
        ).await;

        row_idx += 1;
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles, carga_masiva_id })
}

// ✅ Función común para procesar cada fila (CON AUDITORÍA)
async fn procesar_fila(
    app_state: web::Data<AppState>,
    fila: usize,
    nacionalidad: String,
    cedula: i32,
    primer_nombre: String,
    segundo_nombre: String,
    primer_apellido: String,
    segundo_apellido: String,
    id_rol: i32,
    activo: bool,
    expira: bool,
    exitosos: &mut usize,
    fallidos: &mut usize,
    detalles: &mut Vec<String>,
    carga_masiva_id: Option<i32>,
    pool: &sqlx::PgPool,
) {
    let nombre_completo = format!("{} {}", primer_nombre, primer_apellido);

    // ✅ 1. Validaciones básicas
    if nacionalidad.is_empty() || cedula == 0 || primer_nombre.is_empty() || primer_apellido.is_empty() {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Datos incompletos", fila));
        
        if let Some(carga_id) = carga_masiva_id {
            let _ = registrar_carga_masiva_detalle(
                pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, None, "FALLIDO", Some("Datos incompletos"),
            ).await;
        }
        return;
    }

    if !(nacionalidad == "V" || nacionalidad == "E") {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Nacionalidad inválida (debe ser V o E)", fila));
        
        if let Some(carga_id) = carga_masiva_id {
            let _ = registrar_carga_masiva_detalle(
                pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, None, "FALLIDO", Some("Nacionalidad inválida"),
            ).await;
        }
        return;
    }

    // ✅ 2. Validar contra Oracle AC
    match validar_contra_ac(&nacionalidad, cedula).await {
        Ok(exists) => {
            if !exists {
                *fallidos += 1;
                detalles.push(format!("Fila {}: Cédula {}-{} no existe en AC", fila, nacionalidad, cedula));
                
                if let Some(carga_id) = carga_masiva_id {
                    let _ = registrar_carga_masiva_detalle(
                        pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, None, "FALLIDO", Some("No existe en AC"),
                    ).await;
                }
                return;
            }
        }
        Err(e) => {
            log::warn!("⚠️ Oracle no disponible, saltando validación AC: {}", e);
        }
    }

    // ✅ 3. Generar username y password
    let username = generar_username(&primer_nombre, &primer_apellido, cedula);
    let password = generar_password(&primer_nombre, &primer_apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password.as_bytes()));

    // ✅ 4. Verificar duplicado por USERNAME
    let username_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM usuarios WHERE username = $1)"
    )
    .bind(&username)
    .fetch_one(&app_state.pool_pg)
    .await
    .unwrap_or(false);

    if username_exists {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Username '{}' ya existe (usuario duplicado)", fila, username));
        
        if let Some(carga_id) = carga_masiva_id {
            let _ = registrar_carga_masiva_detalle(
                pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, Some(&username), "FALLIDO", Some("Username duplicado"),
            ).await;
        }
        return;
    }

    // ✅ 5. Verificar duplicado por NACIONALIDAD+CÉDULA
    let cedula_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM usuarios WHERE nacionalidad = $1 AND cedula = $2)"
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .fetch_one(&app_state.pool_pg)
    .await
    .unwrap_or(false);

    if cedula_exists {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Cédula {}-{} ya existe (usuario duplicado)", fila, nacionalidad, cedula));
        
        if let Some(carga_id) = carga_masiva_id {
            let _ = registrar_carga_masiva_detalle(
                pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, Some(&username), "FALLIDO", Some("Cédula duplicada"),
            ).await;
        }
        return;
    }

    // ✅ 6. Insertar usuario CON origen_creacion = 'CARGA_MASIVA'
    let insert_result = sqlx::query(
        r#"
        INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira, id_rol, origen_creacion) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'CARGA_MASIVA')
        RETURNING id
        "#
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .bind(&primer_nombre)
    .bind(&segundo_nombre)
    .bind(&primer_apellido)
    .bind(&segundo_apellido)
    .bind(&username)
    .bind(&hashed_password)
    .bind(activo)
    .bind(expira)
    .bind(id_rol)
    .fetch_optional(&app_state.pool_pg)
    .await;

    match insert_result {
        Ok(Some(row)) => {
            let usuario_id: i32 = row.get(0);
            *exitosos += 1;
            detalles.push(format!("Fila {}: Usuario {} {} creado exitosamente (username: {})", fila, primer_nombre, primer_apellido, username));
            
            if let Some(carga_id) = carga_masiva_id {
                let _ = registrar_carga_masiva_detalle(
                    pool, carga_id, Some(usuario_id), cedula, &nacionalidad, &nombre_completo, Some(&username), "EXITOSO", None,
                ).await;
            }
        }
        Ok(None) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: No se pudo crear el usuario", fila));
            
            if let Some(carga_id) = carga_masiva_id {
                let _ = registrar_carga_masiva_detalle(
                    pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, Some(&username), "FALLIDO", Some("Error al insertar"),
                ).await;
            }
        }
        Err(e) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Error creando usuario {}: {}", fila, primer_nombre, e));
            
            if let Some(carga_id) = carga_masiva_id {
                let _ = registrar_carga_masiva_detalle(
                    pool, carga_id, None, cedula, &nacionalidad, &nombre_completo, Some(&username), "FALLIDO", Some(&e.to_string()),
                ).await;
            }
        }
    }
}

// ✅ Descargar plantilla Excel
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