use actix_web::{web, HttpResponse, Responder};
use actix_multipart::Multipart;
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use csv::ReaderBuilder;
use calamine::{Xlsx, Reader, DataType as CalamineDataType};
use futures_util::TryStreamExt;
use sha2::{Sha256, Digest};
use log;
use crate::structs::AppState;

// Modelo de datos
#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct Usuario {
    pub id: i32,
    pub nacionalidad: String,
    pub cedula: i32,
    pub nombre: String,
    pub apellido: String,
    pub login: String,
    pub password: String,
    pub activo: i32,
    pub expired: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioCreate {
    pub nacionalidad: String,
    pub cedula: i32,
    pub nombre: String,
    pub apellido: String,
    pub login: String,
    pub password: String,
    pub activo: i32,
    pub expired: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioUpdate {
    pub login: String,
    pub password: String,
    pub activo: i32,
    pub expired: i32,
}

// ====== ENDPOINTS PRINCIPALES ======

pub async fn get_usuarios(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, Usuario>(
        "SELECT id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired 
         FROM usuario ORDER BY id DESC"
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

pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    if usuario.login.trim().is_empty() || usuario.password.trim().is_empty() {
        return HttpResponse::BadRequest().body("Login y password son obligatorios");
    }

    let hashed_password = format!("{:x}", Sha256::digest(usuario.password.as_bytes()));

    match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
    )
    .bind(&usuario.nacionalidad)
    .bind(usuario.cedula)
    .bind(&usuario.nombre)
    .bind(&usuario.apellido)
    .bind(&usuario.login)
    .bind(&hashed_password)
    .bind(usuario.activo)
    .bind(usuario.expired)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => HttpResponse::Created().json(user),
        Err(e) => {
            log::error!("Error al crear usuario: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

// Actualizar usuario - solo campos editables
// src/modules/users.rs
pub async fn actualizar_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
    usuario: web::Json<UsuarioUpdate>,
) -> impl Responder {
    let user_id = id.into_inner();
    
    // Obtener usuario existente (TODAS las columnas para coincidir con struct Usuario)
    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired 
         FROM usuario 
         WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => user,
        Err(e) => {
            log::error!("Usuario no encontrado al actualizar: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Usuario no encontrado"
            }));
        }
    };

    // Determinar contraseña: mantener actual si está vacía
    let password_to_use = if usuario.password.trim().is_empty() {
        existing_user.password
    } else {
        format!("{:x}", Sha256::digest(usuario.password.as_bytes()))
    };

    // Actualizar SOLO campos editables
    match sqlx::query_as::<_, Usuario>(
        "UPDATE usuario 
         SET login = $1, 
             password = $2, 
             activo = $3, 
             expired = $4 
         WHERE id = $5 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
    )
    .bind(&usuario.login)
    .bind(&password_to_use)
    .bind(usuario.activo)
    .bind(usuario.expired)
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => {
            log::error!("Error al actualizar usuario {}: {}", user_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error al actualizar usuario",
                "details": e.to_string()
            }))
        }
    }
}



pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
) -> impl Responder {
    let user_id = id.into_inner();

    match sqlx::query_as::<_, Usuario>(
        "UPDATE usuario SET activo = CASE WHEN activo = 1 THEN 0 ELSE 1 END 
         WHERE id = $1 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => {
            log::error!("Error al bloquear usuario {}: {}", user_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

// ====== CARGA MASIVA ======

pub async fn carga_masiva(
    app_state: web::Data<AppState>,
    mut payload: Multipart,
) -> impl Responder {
    let mut file_buffer = Vec::new();
    let mut file_name = String::from("unknown");
    let mut content_type = String::from("application/octet-stream");

    while let Ok(Some(mut field)) = payload.try_next().await {
        if let Some(content_disposition) = field.content_disposition() {
            if let Some(filename) = content_disposition.get_filename() {
                file_name = filename.to_string();
            }
        }
        
        if let Some(mime) = field.content_type() {
            content_type = mime.to_string();
        }

        while let Some(chunk) = field.try_next().await.unwrap_or(None) {
            file_buffer.extend_from_slice(&chunk);
        }
    }

    if file_buffer.is_empty() {
        return HttpResponse::BadRequest().body("No se recibió archivo");
    }

    if file_buffer.len() > 5_000_000 {
        return HttpResponse::BadRequest().body("Archivo excede 5MB");
    }

    let result = if content_type.contains("csv") || file_name.ends_with(".csv") {
        process_csv(&file_buffer, app_state).await
    } else if content_type.contains("excel") || 
              file_name.ends_with(".xlsx") || 
              file_name.ends_with(".xls") {
        process_excel(&file_buffer, app_state).await
    } else {
        return HttpResponse::BadRequest().body("Formato de archivo no soportado");
    };

    match result {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("{} usuarios cargados exitosamente", count)
        })),
        Err(e) => {
            log::error!("Error en carga masiva: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "File processing error",
                "details": e
            }))
        }
    }
}

// Procesamiento de CSV
async fn process_csv(buffer: &[u8], app_state: web::Data<AppState>) -> Result<usize, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(Cursor::new(buffer));
    
    let mut users = Vec::new();

    for result in reader.records() {
        let record = result.map_err(|e| e.to_string())?;
        
        if record.len() < 6 {
            continue;
        }

        let nacionalidad = record.get(0).unwrap_or("").trim().to_string();
        let cedula: i32 = record.get(1).unwrap_or("0").trim().parse().unwrap_or(0);
        let nombre = record.get(2).unwrap_or("").trim().to_string();
        let apellido = record.get(3).unwrap_or("").trim().to_string();
        let login = record.get(4).unwrap_or("").trim().to_string();
        let password = record.get(5).unwrap_or("").trim().to_string();

        if nacionalidad.is_empty() || cedula == 0 || nombre.is_empty() || login.is_empty() {
            continue;
        }

        users.push(UsuarioCreate {
            nacionalidad,
            cedula,
            nombre,
            apellido,
            login,
            password,
            activo: 1,
            expired: 0,
        });
    }

    insert_users_batch(app_state, users).await
}

// Procesamiento de Excel - API CORRECTA para Calamine 0.23
async fn process_excel(buffer: &[u8], app_state: web::Data<AppState>) -> Result<usize, String> {
    let cursor = Cursor::new(buffer.to_vec());
    
    // ✅ USAR Xlsx::new DIRECTAMENTE (API correcta para calamine 0.23)
    let mut workbook = Xlsx::new(cursor)
        .map_err(|e| format!("Error al abrir archivo Excel: {}", e))?;

    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err("No se encontraron hojas en el archivo".to_string());
    }

    // ✅ worksheet_range() devuelve Result<Range, _> DIRECTAMENTE (sin Option)
    let range = workbook
        .worksheet_range(&sheet_names[0])
        .map_err(|e| format!("Error al leer hoja: {}", e))?;

    let mut users = Vec::new();
    let mut row_idx = 0;
    
    for row in range.rows() {
        if row_idx == 0 {
            row_idx += 1;
            continue; // Saltar headers
        }
        
        if row.len() < 6 {
            row_idx += 1;
            continue;
        }

        // ✅ Pattern matching CORRECTO para Calamine 0.23:
        //    - Float e Int son valores (no referencias) gracias a "match ergonomics"
        //    - NO usar *f ni *i (ya son valores directos)
        let nacionalidad = match &row[0] {
            CalamineDataType::String(s) => s.trim().to_string(),
            CalamineDataType::Empty => "".to_string(),
            _ => "".to_string(),
        };

        let cedula = match &row[1] {
            CalamineDataType::Float(f) => *f as i32,  // ✅ f es &f64, necesitamos *f
            CalamineDataType::Int(i) => *i as i32,    // ✅ i es &i64, necesitamos *i
            CalamineDataType::String(s) => s.trim().parse().unwrap_or(0),
            CalamineDataType::Empty => 0,
            _ => 0,
        };

        let nombre = match &row[2] {
            CalamineDataType::String(s) => s.trim().to_string(),
            CalamineDataType::Empty => "".to_string(),
            _ => "".to_string(),
        };

        let apellido = match &row[3] {
            CalamineDataType::String(s) => s.trim().to_string(),
            CalamineDataType::Empty => "".to_string(),
            _ => "".to_string(),
        };

        let login = match &row[4] {
            CalamineDataType::String(s) => s.trim().to_string(),
            CalamineDataType::Empty => "".to_string(),
            _ => "".to_string(),
        };

        let password = match &row[5] {
            CalamineDataType::String(s) => s.trim().to_string(),
            CalamineDataType::Empty => "".to_string(),
            _ => "".to_string(),
        };

        if nacionalidad.is_empty() || cedula == 0 || nombre.is_empty() || login.is_empty() {
            row_idx += 1;
            continue;
        }

        users.push(UsuarioCreate {
            nacionalidad,
            cedula,
            nombre,
            apellido,
            login,
            password,
            activo: 1,
            expired: 0,
        });
        
        row_idx += 1;
    }

    insert_users_batch(app_state, users).await
}

async fn insert_users_batch(
    app_state: web::Data<AppState>,
    users: Vec<UsuarioCreate>,
) -> Result<usize, String> {
    let mut tx = app_state.pool_pg
        .begin()
        .await
        .map_err(|e| format!("Error al iniciar transacción: {}", e))?;

    for user in users.iter() {
        let hashed_password = format!("{:x}", Sha256::digest(user.password.as_bytes()));
        
        sqlx::query(
            "INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (login) DO NOTHING"
        )
        .bind(&user.nacionalidad)
        .bind(user.cedula)
        .bind(&user.nombre)
        .bind(&user.apellido)
        .bind(&user.login)
        .bind(&hashed_password)
        .bind(user.activo)
        .bind(user.expired)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error al insertar usuario {}: {}", user.login, e))?;
    }

    tx.commit()
        .await
        .map_err(|e| format!("Error al confirmar transacción: {}", e))?;

    Ok(users.len())
}