#![allow(dead_code)]
use actix_multipart::Multipart;
use actix_web::{web, Error, HttpResponse, Responder};
use calamine::{DataType as CalamineDataType, Reader, Xls, Xlsx};
use csv::ReaderBuilder;
use futures_util::TryStreamExt;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use sqlx::Row;
use std::io::Cursor;
use std::path::PathBuf;

use crate::middleware::auth::{get_current_user_id, require_admin_or_sistemas};
use crate::structs::AppState;

// ============================================
// ESTRUCTURAS
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

#[derive(Deserialize, Serialize, Debug)]
pub struct CambiarPasswordInicialRequest {
    pub password_actual: String,
    pub password_nueva: String,
    pub password_confirmacion: String,
}

#[derive(Serialize)]
pub struct UsuarioConPassword {
    pub usuario: Usuario,
    pub password_generada: String,
}

#[derive(Serialize)]
pub struct CargaMasivaResultado {
    pub exitosos: usize,
    pub fallidos: usize,
    pub reactivados: usize,
    pub detalles: Vec<String>,
    pub carga_masiva_id: Option<i32>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ============================================
// ESTRUCTURAS PARA VALIDACIÓN CON DISCREPANCIAS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACData {
    pub nacionalidad: String,
    pub cedula: i32,
    pub primer_nombre: String,
    pub segundo_nombre: String,
    pub primer_apellido: String,
    pub segundo_apellido: String,
    pub status_objecion: Option<i32>,
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
    pub estado: String,
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
// ESTRUCTURAS PARA DESCARGAR EXCEL
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
// HELPERS
// ============================================

fn obtener_id_usuario_del_token(req: &actix_web::HttpRequest) -> Result<i32, String> {
    get_current_user_id(req).map_err(|_| "Token inválido".to_string())
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

fn validar_longitud_cedula(cedula: i32) -> bool {
    let cedula_str = cedula.to_string();
    cedula_str.len() >= 6 && cedula_str.len() <= 8
}

// ============================================
// CONSULTAR AC CON DATOS COMPLETOS
// ============================================

async fn consultar_ac(nacionalidad: &str, cedula: i32) -> Result<Option<ACData>, String> {
    use oracle::Connection;
    use std::env;

    let username =
        env::var("ORACLE_USER").map_err(|e| format!("ORACLE_USER no configurado: {}", e))?;
    let password =
        env::var("ORACLE_PASS").map_err(|e| format!("ORACLE_PASS no configurado: {}", e))?;
    let oracle_ip =
        env::var("ORACLE_IP").map_err(|e| format!("ORACLE_IP no configurado: {}", e))?;
    let oracle_port =
        env::var("ORACLE_PORT").map_err(|e| format!("ORACLE_PORT no configurado: {}", e))?;
    let oracle_db =
        env::var("ORACLE_DB").map_err(|e| format!("ORACLE_DB no configurado: {}", e))?;

    log::info!("🔗 Oracle: {}@{}:{}/{}", username, oracle_ip, oracle_port, oracle_db);

    let connect_string = format!("//{}:{}/{}", oracle_ip, oracle_port, oracle_db);

    let conn = Connection::connect(&username, &password, &connect_string).map_err(|e| {
        log::error!("❌ Error Oracle: {}", e);
        format!("Error conectando a Oracle: {}", e)
    })?;

    let sql = "SELECT NACIONALIDAD, CEDULA, PRIMER_NOMBRE, NVL(SEGUNDO_NOMBRE, '') as SEGUNDO_NOMBRE,
                      PRIMER_APELLIDO, NVL(SEGUNDO_APELLIDO, '') as SEGUNDO_APELLIDO, STATUS_OBJECION
               FROM RE.AC
               WHERE NACIONALIDAD = :nacionalidad AND CEDULA = :cedula";

    let mut cursor = conn
        .query(sql, &[&nacionalidad, &cedula])
        .map_err(|e| format!("Error query AC: {}", e))?;

    if let Some(row) = cursor
        .next()
        .transpose()
        .map_err(|e| format!("Error leyendo AC: {}", e))?
    {
        Ok(Some(ACData {
            nacionalidad: row.get(0).unwrap_or_else(|_| nacionalidad.to_string()),
            cedula: row.get(1).unwrap_or(cedula),
            primer_nombre: row.get(2).unwrap_or_default(),
            segundo_nombre: row.get(3).unwrap_or_default(),
            primer_apellido: row.get(4).unwrap_or_default(),
            segundo_apellido: row.get(5).unwrap_or_default(),
            status_objecion: row.get(6).ok(),
        }))
    } else {
        Ok(None)
    }
}

// ============================================
// COMPARAR DATOS EXCEL VS AC
// ============================================

fn comparar_datos(excel: &FilaPreview, ac: &ACData) -> Vec<Discrepancia> {
    let mut discrepancias = Vec::new();
    let normalize = |s: &str| -> String {
        s.to_uppercase()
            .replace('Á', "A")
            .replace('É', "E")
            .replace('Í', "I")
            .replace('Ó', "O")
            .replace('Ú', "U")
            .replace('Ñ', "N")
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
// AUDITORÍA DE CARGA MASIVA
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
        "#,
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
        VALUES ($1, $2, $3, $4, UPPER($5), $6, $7, $8)
        "#,
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
// CRUD USUARIOS
// ============================================

pub async fn get_usuarios(
    req: actix_web::HttpRequest,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    match sqlx::query_as::<_, UsuarioConRol>(
        "SELECT u.id, u.id_rol, COALESCE(r.nombre_rol, 'Sin Rol') AS nombre_rol,
                u.nacionalidad, u.cedula, u.primer_nombre, u.segundo_nombre,
                u.primer_apellido, u.segundo_apellido, u.username, u.activo, u.expira
         FROM usuarios u LEFT JOIN roles r ON u.id_rol = r.id
         WHERE u.eliminado = FALSE ORDER BY u.id DESC",
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

pub async fn get_roles(
    req: actix_web::HttpRequest,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    match sqlx::query_as::<_, (i32, String)>("SELECT id, nombre_rol FROM roles ORDER BY id ASC")
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

pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let nacionalidad = usuario.nacionalidad.trim().to_uppercase();
    let cedula = usuario.cedula;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return HttpResponse::BadRequest().body("nacionalidad debe ser V o E");
    }
    if !validar_longitud_cedula(cedula) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cédula inválida",
            "codigo": "CEDULA_LONGITUD_INVALIDA",
            "detalle": "Ingrese una cédula válida (6-8 dígitos)"
        }));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return HttpResponse::BadRequest().body("cedula inválida");
    }

    if let Ok(Some(ac_data)) = consultar_ac(&nacionalidad, cedula).await {
        if ac_data.status_objecion != Some(0) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No se puede crear el usuario",
                "codigo": "PRESENTA OBJECION",
                "detalle": "La cédula consultada presenta objeción en el AC"
            }));
        }
    }

    let usuario_existente = sqlx::query(
        r#"SELECT id, eliminado FROM usuarios WHERE nacionalidad = $1 AND cedula = $2 LIMIT 1"#,
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
         VALUES ($1, $2, UPPER($3), UPPER($4), UPPER($5), UPPER($6), $7, $8, $9, $10, $11, 'MANUAL')
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
                   primer_apellido, segundo_apellido, username, password, activo, expira",
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
    .bind(true)
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
    let autor_id = obtener_id_usuario_del_token(&req).ok();

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
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = TRUE",
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

    match sqlx::query(
        r#"UPDATE usuarios SET eliminado = FALSE, eliminado_en = NULL, eliminado_por = NULL WHERE id = $1"#,
    )
    .bind(user_id)
    .execute(&app_state.pool_pg)
    .await
    {
        Ok(_) => {
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);
            let autor_id = obtener_id_usuario_del_token(&req).ok();

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
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1",
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
        "UPDATE usuarios SET password = $1, activo = $2, expira = $3, id_rol = $4
         WHERE id = $5 RETURNING id, id_rol, nacionalidad, cedula, primer_nombre,
         segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira",
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
    let autor_id = obtener_id_usuario_del_token(&req).ok();

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

pub async fn cambiar_password_inicial(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    body: web::Json<CambiarPasswordInicialRequest>,
) -> impl Responder {
    let user_id = match get_current_user_id(&req) {
        Ok(id) => id,
        Err(res) => return res,
    };

    let password_actual = body.password_actual.trim();
    let password_nueva = body.password_nueva.trim();
    let password_confirmacion = body.password_confirmacion.trim();

    if password_actual.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Ingrese la contraseña actual"
        }));
    }

    if password_nueva.len() < 6 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "La nueva contraseña debe tener mínimo 6 caracteres"
        }));
    }

    if password_nueva != password_confirmacion {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "La confirmación no coincide con la nueva contraseña"
        }));
    }

    if password_actual == password_nueva {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "La nueva contraseña debe ser diferente a la contraseña actual"
        }));
    }

    let password_actual_hash = format!(
        "{:x}",
        Sha256::digest(password_actual.as_bytes())
    );

    let usuario = match sqlx::query(
        "SELECT id, password, activo, eliminado FROM usuarios WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&app_state.pool_pg)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado"
            }));
        }
        Err(e) => {
            log::error!("Error consultando usuario para cambio de contraseña: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error interno del servidor"
            }));
        }
    };

    let activo: bool = usuario.get("activo");
    let eliminado: bool = usuario.get("eliminado");

    if !activo || eliminado {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Usuario no autorizado para cambiar contraseña"
        }));
    }

    let password_bd: String = usuario.get("password");

    if password_bd != password_actual_hash {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "La contraseña actual es incorrecta"
        }));
    }

    let nueva_hash = format!(
        "{:x}",
        Sha256::digest(password_nueva.as_bytes())
    );

    match sqlx::query(
        "UPDATE usuarios SET password = $1, expira = FALSE WHERE id = $2"
    )
    .bind(nueva_hash)
    .bind(user_id)
    .execute(&app_state.pool_pg)
    .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Contraseña actualizada correctamente"
        })),
        Err(e) => {
            log::error!("Error actualizando contraseña inicial: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "No se pudo actualizar la contraseña"
            }))
        }
    }
}

pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    id: web::Path<i32>,
) -> impl Responder {
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1",
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
        "UPDATE usuarios SET activo = NOT activo WHERE id = $1
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
                   primer_apellido, segundo_apellido, username, password, activo, expira",
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => {
            let ip_origen = extract_ip(&req);
            let user_agent = extract_user_agent(&req);
            let autor_id = obtener_id_usuario_del_token(&req).ok();

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
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre,
         primer_apellido, segundo_apellido, username, password, activo, expira
         FROM usuarios WHERE id = $1 AND eliminado = FALSE",
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
    let autor_id = obtener_id_usuario_del_token(&req).ok();

    match sqlx::query(
        r#"UPDATE usuarios SET eliminado = TRUE, eliminado_en = CURRENT_TIMESTAMP,
           eliminado_por = $2 WHERE id = $1"#,
    )
    .bind(user_id)
    .bind(&autor_id)
    .execute(&app_state.pool_pg)
    .await
    {
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
// VALIDAR CARGA MASIVA (PREVIEW)
// ============================================

pub async fn validar_carga_masiva(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    mut payload: Multipart,
) -> impl Responder {
    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

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

    let result = if file_name.ends_with(".xlsx") {
        validar_xlsx_preview(&file_buffer, app_state.clone()).await
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
// CONFIRMAR CARGA MASIVA (CON REACTIVACIÓN)
// ============================================

pub async fn confirmar_carga_masiva(
    app_state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    body: web::Json<ConfirmarCargaRequest>,
) -> impl Responder {
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log, LogEntry};

    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let ip_origen = extract_ip(&req);
    let user_agent = extract_user_agent(&req);
    let autor_id = obtener_id_usuario_del_token(&req).ok();

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
        )
        .await
        {
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

        if !validar_longitud_cedula(fila.cedula) {
            fallidos += 1;
            detalles.push(format!(
                "Fila {}: {}",
                fila.fila, "Ingrese una cédula válida (6-8 dígitos)"
            ));

            if let Some(carga_id) = carga_masiva_id {
                let _ = registrar_carga_masiva_detalle(
                    &app_state.pool_pg,
                    carga_id,
                    None,
                    fila.cedula,
                    &fila.nacionalidad,
                    &nombre_completo,
                    Some(&username),
                    "FALLIDO",
                    Some("Cédula inválida: debe tener 6-8 dígitos"),
                )
                .await;
            }
            continue;
        }

        if let Ok(Some(ac_data)) = consultar_ac(&fila.nacionalidad, fila.cedula).await {
            if ac_data.status_objecion != Some(0) {
                fallidos += 1;
                detalles.push(format!(
                    "Fila {}: Cédula {}-{} registra objeción en AC",
                    fila.fila, fila.nacionalidad, fila.cedula
                ));
                continue;
            }
        }

        let cedula_existente = sqlx::query(
            "SELECT id, eliminado FROM usuarios WHERE nacionalidad = $1 AND cedula = $2",
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
                           activo = TRUE, expira = TRUE, id_rol = $8, username = $9
                           WHERE id = $10"#,
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
                    .await
                    {
                        Ok(_) => {
                            exitosos += 1;
                            reactivados += 1;
                            detalles.push(format!(
                                "Fila {}: Usuario {} {} REACTIVADO por cédula (usuario: {})",
                                fila.fila, fila.primer_nombre, fila.primer_apellido, username
                            ));

                            if let Some(carga_id) = carga_masiva_id {
                                let _ = registrar_carga_masiva_detalle(
                                    &app_state.pool_pg,
                                    carga_id,
                                    Some(usuario_id),
                                    fila.cedula,
                                    &fila.nacionalidad,
                                    &nombre_completo,
                                    Some(&username),
                                    "REACTIVADO",
                                    None,
                                )
                                .await;
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
                            detalles.push(format!(
                                "Fila {}: Error reactivando usuario por cédula: {}",
                                fila.fila, e
                            ));
                        }
                    }
                    continue;
                } else {
                    fallidos += 1;
                    detalles.push(format!(
                        "Fila {}: Cédula {}-{} ya existe (usuario activo)",
                        fila.fila, fila.nacionalidad, fila.cedula
                    ));
                    if let Some(carga_id) = carga_masiva_id {
                        let _ = registrar_carga_masiva_detalle(
                            &app_state.pool_pg,
                            carga_id,
                            None,
                            fila.cedula,
                            &fila.nacionalidad,
                            &nombre_completo,
                            Some(&username),
                            "FALLIDO",
                            Some("Cédula duplicada (activa)"),
                        )
                        .await;
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

        let insert_result = sqlx::query(
            r#"INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre,
               primer_apellido, segundo_apellido, username, password, activo, expira, id_rol, origen_creacion)
               VALUES ($1, $2, UPPER($3), UPPER($4), UPPER($5), UPPER($6), $7, $8, $9, $10, $11, 'CARGA_MASIVA')
               RETURNING id"#,
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
        .bind(true)
        .bind(fila.id_rol)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match insert_result {
            Ok(Some(row)) => {
                let usuario_id: i32 = row.get(0);
                exitosos += 1;
                detalles.push(format!(
                    "Fila {}: Usuario {} {} creado (username: {})",
                    fila.fila, fila.primer_nombre, fila.primer_apellido, username
                ));
                if let Some(carga_id) = carga_masiva_id {
                    let _ = registrar_carga_masiva_detalle(
                        &app_state.pool_pg,
                        carga_id,
                        Some(usuario_id),
                        fila.cedula,
                        &fila.nacionalidad,
                        &nombre_completo,
                        Some(&username),
                        "EXITOSO",
                        None,
                    )
                    .await;
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
            r#"UPDATE carga_masiva_logs SET total_filas = $1, exitosos = $2, fallidos = $3, detalles = $4 WHERE id = $5"#,
        )
        .bind(&((exitosos + fallidos) as i32))
        .bind(&(exitosos as i32))
        .bind(&(fallidos as i32))
        .bind(&detalles_json)
        .bind(carga_id)
        .execute(&app_state.pool_pg)
        .await;
    }

    let log_entry = LogEntry {
        id_tipo_accion: 2,
        id_accion: 7,
        id_usuario: autor_id,
        accion: "CARGA MASIVA DE USUARIOS".to_string(),
        cedula_relacionada: carga_masiva_id,
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
// FUNCIONES DE VALIDACIÓN PREVIEW
// ============================================

async fn validar_csv_preview(
    buffer: &[u8],
    app_state: web::Data<AppState>,
) -> Result<CargaMasivaPreview, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(Cursor::new(buffer));
    let mut filas = Vec::new();
    let mut row_idx = 0;

    for result in reader.records() {
        row_idx += 1;
        if row_idx == 1 {
            continue;
        }

        let record =
            result.map_err(|e| format!("Error leyendo CSV línea {}: {}", row_idx, e))?;
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
                mensaje_error: Some("Columnas insuficientes (se esperan 6)".to_string()),
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
        )
        .await;

        filas.push(fila_preview);
    }

    Ok(calcular_resumen_preview(filas))
}

async fn validar_xlsx_preview(
    buffer: &[u8],
    app_state: web::Data<AppState>,
) -> Result<CargaMasivaPreview, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xlsx::new(cursor).map_err(|e| format!("Error abriendo XLSX: {}", e))?;
    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLSX".to_string());
    }
    let range = workbook
        .worksheet_range(&sheet_names[0])
        .map_err(|e| format!("Error leyendo hoja: {}", e))?;
    validar_range_preview(range, app_state).await
}

async fn validar_xls_preview(
    buffer: &[u8],
    app_state: web::Data<AppState>,
) -> Result<CargaMasivaPreview, String> {
    let cursor = Cursor::new(buffer.to_vec());
    let mut workbook = Xls::new(cursor).map_err(|e| format!("Error abriendo XLS: {}", e))?;
    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo XLS".to_string());
    }
    let range = workbook
        .worksheet_range(&sheet_names[0])
        .map_err(|e| format!("Error leyendo hoja: {}", e))?;
    validar_range_preview(range, app_state).await
}

async fn validar_range_preview(
    range: calamine::Range<CalamineDataType>,
    app_state: web::Data<AppState>,
) -> Result<CargaMasivaPreview, String> {
    let mut filas = Vec::new();
    let mut row_idx = 0;

    for row in range.rows() {
        row_idx += 1;
        if row_idx == 1 {
            continue;
        }
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
                mensaje_error: Some("Columnas insuficientes (se esperan 6)".to_string()),
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
        )
        .await;

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
    if nacionalidad.is_empty()
        || cedula == 0
        || excel_primer_nombre.is_empty()
        || excel_primer_apellido.is_empty()
    {
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

    if !validar_longitud_cedula(cedula) {
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
            mensaje_error: Some("Ingrese una cédula válida (6-8 dígitos)".to_string()),
        };
    }

    match consultar_ac(&nacionalidad, cedula).await {
        Ok(Some(ac_data)) => {
            if ac_data.status_objecion != Some(0) {
                return FilaPreview {
                    fila,
                    nacionalidad,
                    cedula,
                    estado: "RECHAZADO".to_string(),
                    excel_primer_nombre,
                    excel_segundo_nombre,
                    excel_primer_apellido,
                    excel_segundo_apellido,
                    ac_primer_nombre: Some(ac_data.primer_nombre.clone()),
                    ac_segundo_nombre: Some(ac_data.segundo_nombre.clone()),
                    ac_primer_apellido: Some(ac_data.primer_apellido.clone()),
                    ac_segundo_apellido: Some(ac_data.segundo_apellido.clone()),
                    discrepancias: vec![],
                    mensaje_error: Some(
                        "⚠️ La cédula registra presenta objeción en el AC".to_string(),
                    ),
                };
            }

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
// DESCARGAR PLANTILLA
// ============================================

pub async fn descargar_plantilla(
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if let Err(res) = require_admin_or_sistemas(&req) {
        return Ok(res);
    }

    info!("📥 Sirviendo plantilla Excel");
    let file_path = PathBuf::from("files/templates/plantilla.xlsx");
    if !file_path.exists() {
        return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Plantilla no encontrada en el servidor".to_string(),
        }));
    }
    let file_bytes = std::fs::read(&file_path)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    info!("✅ Plantilla enviada: {} bytes", file_bytes.len());
    Ok(HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=\"plantilla_usuarios.xlsx\"",
        ))
        .body(file_bytes))
}

// ============================================
// DESCARGAR EXCEL DE CARGA MASIVA
// ============================================

pub async fn descargar_carga_masiva_excel(
    req: actix_web::HttpRequest,
    app_state: web::Data<AppState>,
    path: web::Path<i32>,
) -> impl Responder {
    if let Err(res) = require_admin_or_sistemas(&req) {
        return res;
    }

    let carga_masiva_id = path.into_inner();

    log::info!("📥 Descargando Excel para carga_masiva_id: {}", carga_masiva_id);

    let detalles = match sqlx::query_as::<_, CargaMasivaDetalle>(
        r#"
        SELECT id, carga_masiva_id, usuario_id, cedula, nacionalidad,
               nombre_completo, username, estado, error_detalle, created_at
        FROM carga_masiva_detalles
        WHERE carga_masiva_id = $1
        ORDER BY id ASC
        "#,
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
    log::info!(
        "📊 Exitosos: {}",
        detalles
            .iter()
            .filter(|d| d.estado == "EXITOSO" || d.estado == "REACTIVADO")
            .count()
    );
    log::info!(
        "📊 Fallidos: {}",
        detalles
            .iter()
            .filter(|d| d.estado == "FALLIDO" || d.estado == "INVALIDO" || d.estado == "RECHAZADO")
            .count()
    );

    if detalles.is_empty() {
        log::warn!(
            "⚠️ No se encontraron detalles para carga_masiva_id: {}",
            carga_masiva_id
        );
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("No se encontraron detalles para carga_masiva_id {}", carga_masiva_id)
        }));
    }

    use rust_xlsxwriter::{Format, FormatAlign, FormatBorder, Workbook};

    let mut workbook = Workbook::new();

    let header_format = Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_border(FormatBorder::Thin)
        .set_background_color(rust_xlsxwriter::Color::Green);

    let normal_format = Format::new();

    let sheet = workbook.add_worksheet().set_name("Exitosos").unwrap();

    let headers = ["Nacionalidad", "Cédula", "Nombre Completo", "Username", "Estado"];
    for (col, header) in headers.iter().enumerate() {
        sheet
            .write_string_with_format(0, col as u16, *header, &header_format)
            .unwrap();
    }

    let mut row = 1;
    for detalle in &detalles {
        if detalle.estado == "EXITOSO" || detalle.estado == "REACTIVADO" {
            sheet
                .write_string_with_format(row, 0, &detalle.nacionalidad, &normal_format)
                .unwrap();
            sheet
                .write_number_with_format(row, 1, detalle.cedula as f64, &normal_format)
                .unwrap();
            sheet
                .write_string_with_format(row, 2, &detalle.nombre_completo, &normal_format)
                .unwrap();
            sheet
                .write_string_with_format(
                    row,
                    3,
                    detalle.username.as_deref().unwrap_or(""),
                    &normal_format,
                )
                .unwrap();
            sheet
                .write_string_with_format(row, 4, &detalle.estado, &normal_format)
                .unwrap();
            row += 1;
        }
    }

    let sheet = workbook.add_worksheet().set_name("Fallidos").unwrap();

    let headers = ["Nacionalidad", "Cédula", "Nombre Completo", "Username", "Estado", "Error"];
    for (col, header) in headers.iter().enumerate() {
        sheet
            .write_string_with_format(0, col as u16, *header, &header_format)
            .unwrap();
    }

    let mut row = 1;
    for detalle in &detalles {
        if detalle.estado == "FALLIDO" || detalle.estado == "INVALIDO" || detalle.estado == "RECHAZADO" {
            sheet
                .write_string_with_format(row, 0, &detalle.nacionalidad, &normal_format)
                .unwrap();
            sheet
                .write_number_with_format(row, 1, detalle.cedula as f64, &normal_format)
                .unwrap();
            sheet
                .write_string_with_format(row, 2, &detalle.nombre_completo, &normal_format)
                .unwrap();
            sheet
                .write_string_with_format(
                    row,
                    3,
                    detalle.username.as_deref().unwrap_or(""),
                    &normal_format,
                )
                .unwrap();
            sheet
                .write_string_with_format(row, 4, &detalle.estado, &normal_format)
                .unwrap();
            sheet
                .write_string_with_format(
                    row,
                    5,
                    detalle.error_detalle.as_deref().unwrap_or(""),
                    &normal_format,
                )
                .unwrap();
            row += 1;
        }
    }

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

    let nombre_archivo = format!(
        "carga_masiva_{}_{}.xlsx",
        carga_masiva_id,
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );

    log::info!("✅ Excel generado: {}", nombre_archivo);

    HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", nombre_archivo),
        ))
        .body(buffer)
}