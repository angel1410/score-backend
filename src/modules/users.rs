// users.rs
use actix_web::{web, HttpResponse, Responder};
use actix_multipart::Multipart;
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use csv::ReaderBuilder;
use calamine::{DataType as CalamineDataType, Reader, Xls, Xlsx};
use futures_util::TryStreamExt;
use sha2::{Sha256, Digest};
use log;
use crate::structs::AppState;

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
    pub id_rol: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioCreate {
    pub nacionalidad: String,
    pub cedula: i32,
    pub nombre: String,
    pub apellido: String,
    pub id_rol: i32,
    pub activo: i32,
    pub expired: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UsuarioUpdate {
    pub password: Option<String>,
    pub activo: i32,
    pub expired: i32,
    pub id_rol: i32,
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
    pub detalles: Vec<String>,
}

fn generar_login(nombre: &str, apellido: &str, _cedula: i32) -> String {
    let inicial_nombre = nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();

    let apellido_limpio = apellido.trim().to_lowercase();

    format!("{}{}", inicial_nombre, apellido_limpio)
}

fn generar_password(nombre: &str, apellido: &str, cedula: i32) -> String {
    let inicial_nombre = nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();

    let inicial_apellido = apellido
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();

    format!("{}{}{}", inicial_nombre, inicial_apellido, cedula)
}

// ✅ VALIDACIÓN lógica (sin tocar DB): no duplicar por nacionalidad+cedula
async fn existe_usuario_por_cedula(
    app_state: &AppState,
    nacionalidad: &str,
    cedula: i32,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT 1
        FROM usuario
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

pub async fn get_usuarios(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, Usuario>(
        "SELECT 
            u.id, 
            u.nacionalidad, 
            u.cedula, 
            u.nombre, 
            u.apellido, 
            u.login, 
            u.password, 
            u.activo, 
            u.expired,
            COALESCE(ru.id_rol, 1) AS id_rol
         FROM usuario u
         LEFT JOIN rol_usuario ru ON u.id = ru.id_usuario
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

pub async fn get_roles(
    app_state: web::Data<AppState>,
) -> impl Responder {
    match sqlx::query_as::<_, (i32, String)>(
        "SELECT id_rol, nombre FROM rol ORDER BY id_rol"
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

// ✅ Crear usuario con validación de cédula duplicada (409)
pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    let nacionalidad = usuario.nacionalidad.trim().to_uppercase();
    let cedula = usuario.cedula;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return HttpResponse::BadRequest().body("nacionalidad debe ser V o E");
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return HttpResponse::BadRequest().body("cedula inválida");
    }

    match existe_usuario_por_cedula(&app_state, &nacionalidad, cedula).await {
        Ok(true) => return HttpResponse::Conflict().body("Ya existe un usuario con esa cédula"),
        Ok(false) => {}
        Err(e) => {
            log::error!("Error validando duplicado por cédula: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    }

    let login = generar_login(&usuario.nombre, &usuario.apellido, cedula);
    let password_generada = generar_password(&usuario.nombre, &usuario.apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password_generada.as_bytes()));

    let user = match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired, 1 AS id_rol"
    )
    .bind(&nacionalidad)
    .bind(cedula)
    .bind(&usuario.nombre)
    .bind(&usuario.apellido)
    .bind(&login)
    .bind(&hashed_password)
    .bind(usuario.activo)
    .bind(usuario.expired)
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

    if let Err(e) = sqlx::query(
        "INSERT INTO rol_usuario (id_rol, id_usuario) VALUES ($1, $2)"
    )
    .bind(usuario.id_rol)
    .bind(user.id)
    .execute(&app_state.pool_pg)
    .await
    {
        log::error!("Error al asignar rol: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Error al asignar rol",
            "details": e.to_string()
        }));
    }

    let mut user_with_rol = user;
    user_with_rol.id_rol = usuario.id_rol;

    HttpResponse::Created().json(UsuarioConPassword {
        usuario: user_with_rol,
        password_generada,
    })
}

pub async fn actualizar_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
    usuario: web::Json<UsuarioUpdate>,
) -> impl Responder {
    let user_id = id.into_inner();

    let existing_user = match sqlx::query_as::<_, Usuario>(
        "SELECT id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired, 
                COALESCE((SELECT id_rol FROM rol_usuario WHERE id_usuario = $1), 1) AS id_rol
         FROM usuario WHERE id = $1"
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
        "UPDATE usuario SET password = $1, activo = $2, expired = $3 WHERE id = $4 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired, $5 AS id_rol"
    )
    .bind(&password_to_use)
    .bind(usuario.activo)
    .bind(usuario.expired)
    .bind(user_id)
    .bind(usuario.id_rol)
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

    if let Err(e) = sqlx::query(
        "UPDATE rol_usuario SET id_rol = $1 WHERE id_usuario = $2"
    )
    .bind(usuario.id_rol)
    .bind(user_id)
    .execute(&app_state.pool_pg)
    .await
    {
        log::error!("Error al actualizar rol: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Error al actualizar rol",
            "details": e.to_string()
        }));
    }

    HttpResponse::Ok().json(updated_user)
}

pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
) -> impl Responder {
    let user_id = id.into_inner();

    match sqlx::query_as::<_, Usuario>(
        "UPDATE usuario SET activo = CASE WHEN activo = 1 THEN 0 ELSE 1 END 
         WHERE id = $1 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired, 
                  COALESCE((SELECT id_rol FROM rol_usuario WHERE id_usuario = $1), 1) AS id_rol"
    )
    .bind(user_id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => {
            log::error!("Error al bloquear usuario: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }))
        }
    }
}

// ✅ NUEVO: ELIMINAR USUARIO (con transacción)
// - borra rol_usuario primero
// - luego borra usuario
pub async fn eliminar_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
) -> impl Responder {
    let user_id = id.into_inner();

    // Verificar existencia
    let exists = match sqlx::query_scalar::<_, i32>("SELECT 1 FROM usuario WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&app_state.pool_pg)
        .await
    {
        Ok(v) => v.is_some(),
        Err(e) => {
            log::error!("Error verificando usuario: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    };

    if !exists {
        return HttpResponse::NotFound().body("Usuario no encontrado");
    }

    let mut tx = match app_state.pool_pg.begin().await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Error iniciando transacción: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error",
                "details": e.to_string()
            }));
        }
    };

    if let Err(e) = sqlx::query("DELETE FROM rol_usuario WHERE id_usuario = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        log::error!("Error eliminando rol_usuario: {}", e);
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Error eliminando rol del usuario",
            "details": e.to_string()
        }));
    }

    if let Err(e) = sqlx::query("DELETE FROM usuario WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        log::error!("Error eliminando usuario: {}", e);
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Error eliminando usuario",
            "details": e.to_string()
        }));
    }

    if let Err(e) = tx.commit().await {
        log::error!("Error commit delete: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Error interno",
            "details": e.to_string()
        }));
    }

    HttpResponse::Ok().body("Usuario eliminado")
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

    let connect_string = format!("//{}:{}{}", oracle_ip, oracle_port, oracle_db);

    let conn = Connection::connect(&username, &password, &connect_string)
        .map_err(|e| format!("Error conectando a Oracle: {}", e))?;

    let sql = "SELECT 1 FROM RE.AC WHERE NACIONALIDAD = :nacionalidad AND CEDULA = :cedula";

    let exists = conn
        .query_row_as::<i32>(sql, &[&nacionalidad, &cedula])
        .ok()
        .is_some();

    Ok(exists)
}

// ====== CARGA MASIVA COMPLETA CON VALIDACIÓN ======
pub async fn carga_masiva(
    app_state: web::Data<AppState>,
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

    if file_buffer.len() > 5_000_000 {
        return HttpResponse::BadRequest().body("Archivo excede 5MB");
    }

    let result = if file_name.ends_with(".csv") {
        process_csv(&file_buffer, app_state).await
    } else if file_name.ends_with(".xlsx") {
        process_excel_xlsx(&file_buffer, app_state).await
    } else if file_name.ends_with(".xls") {
        process_excel_xls(&file_buffer, app_state).await
    } else {
        return HttpResponse::BadRequest().body("Formato no soportado. Use .csv, .xlsx o .xls");
    };

    match result {
        Ok(res) => HttpResponse::Ok().json(res),
        Err(e) => {
            log::error!("Error en carga masiva: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error procesando archivo",
                "details": e
            }))
        }
    }
}

async fn process_csv(
    buffer: &[u8],
    app_state: web::Data<AppState>
) -> Result<CargaMasivaResultado, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(Cursor::new(buffer));

    let mut exitosos = 0;
    let mut fallidos = 0;
    let mut detalles = Vec::new();

    for (idx, result) in reader.records().enumerate() {
        let record = result.map_err(|e| format!("Error leyendo CSV línea {}: {}", idx + 2, e))?;

        if record.len() < 7 {
            fallidos += 1;
            detalles.push(format!("Línea {}: Columnas insuficientes (se esperan 7)", idx + 2));
            continue;
        }

        let nacionalidad = record.get(0).unwrap_or("").trim().to_uppercase();
        let cedula: i32 = record.get(1).unwrap_or("0").trim().parse().unwrap_or(0);
        let nombre = record.get(2).unwrap_or("").trim().to_string();
        let apellido = record.get(3).unwrap_or("").trim().to_string();
        let id_rol: i32 = record.get(4).unwrap_or("0").trim().parse().unwrap_or(0);
        let activo: i32 = record.get(5).unwrap_or("1").trim().parse().unwrap_or(1);
        let expired: i32 = record.get(6).unwrap_or("0").trim().parse().unwrap_or(0);

        match validar_contra_ac(&nacionalidad, cedula).await {
            Ok(exists) => {
                if !exists {
                    fallidos += 1;
                    detalles.push(format!(
                        "Línea {}: Cédula {}-{} no existe en registro electoral",
                        idx + 2, nacionalidad, cedula
                    ));
                    continue;
                }
            }
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Línea {}: Error validando en AC: {}", idx + 2, e));
                continue;
            }
        }

        // ✅ Bloquear duplicado por cédula
        match existe_usuario_por_cedula(&app_state, &nacionalidad, cedula).await {
            Ok(true) => {
                fallidos += 1;
                detalles.push(format!(
                    "Línea {}: Ya existe un usuario con cédula {}-{} (duplicado)",
                    idx + 2, nacionalidad, cedula
                ));
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Línea {}: Error verificando duplicado: {}", idx + 2, e));
                continue;
            }
        }

        let login = generar_login(&nombre, &apellido, cedula);
        let password = generar_password(&nombre, &apellido, cedula);
        let hashed_password = format!("{:x}", Sha256::digest(password.as_bytes()));

        let tx_result = sqlx::query(
            r#"
            INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (login) DO NOTHING
            RETURNING id
            "#
        )
        .bind(&nacionalidad)
        .bind(cedula)
        .bind(&nombre)
        .bind(&apellido)
        .bind(&login)
        .bind(&hashed_password)
        .bind(activo)
        .bind(expired)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match tx_result {
            Ok(Some(_)) => {
                if let Ok(user_id) = sqlx::query_scalar::<_, i32>(
                    "SELECT id FROM usuario WHERE login = $1"
                )
                .bind(&login)
                .fetch_one(&app_state.pool_pg)
                .await
                {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO rol_usuario (id_rol, id_usuario) VALUES ($1, $2)
                        ON CONFLICT (id_usuario) DO UPDATE SET id_rol = $1
                        "#
                    )
                    .bind(id_rol)
                    .bind(user_id)
                    .execute(&app_state.pool_pg)
                    .await;

                    exitosos += 1;
                    detalles.push(format!(
                        "Línea {}: Usuario {} creado exitosamente (login: {})",
                        idx + 2, nombre, login
                    ));
                } else {
                    fallidos += 1;
                    detalles.push(format!("Línea {}: No se pudo obtener ID del usuario {}", idx + 2, nombre));
                }
            }
            Ok(None) => {
                fallidos += 1;
                detalles.push(format!("Línea {}: Login '{}' ya existe (usuario duplicado)", idx + 2, login));
            }
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Línea {}: Error creando usuario {}: {}", idx + 2, nombre, e));
            }
        }
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles })
}

async fn process_excel_xlsx(
    buffer: &[u8],
    app_state: web::Data<AppState>
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

    process_excel_range(range, app_state).await
}

async fn process_excel_xls(
    buffer: &[u8],
    app_state: web::Data<AppState>
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

    process_excel_range(range, app_state).await
}

async fn process_excel_range(
    range: calamine::Range<CalamineDataType>,
    app_state: web::Data<AppState>,
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

        if row.len() < 7 {
            fallidos += 1;
            detalles.push(format!("Fila {}: Columnas insuficientes", row_idx + 1));
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

        let nombre = match &row[2] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let apellido = match &row[3] {
            CalamineDataType::String(s) => s.trim().to_string(),
            _ => "".to_string(),
        };

        let id_rol = match &row[4] {
            CalamineDataType::Float(f) => *f as i32,
            CalamineDataType::String(s) => s.trim().parse().unwrap_or(0),
            _ => 0,
        };

        let activo = match &row[5] {
            CalamineDataType::Float(f) => *f as i32,
            CalamineDataType::String(s) => s.trim().parse().unwrap_or(1),
            _ => 1,
        };

        let expired = match &row[6] {
            CalamineDataType::Float(f) => *f as i32,
            CalamineDataType::String(s) => s.trim().parse().unwrap_or(0),
            _ => 0,
        };

        if nacionalidad.is_empty() || cedula == 0 || nombre.is_empty() || id_rol == 0 {
            fallidos += 1;
            detalles.push(format!("Fila {}: Datos incompletos", row_idx + 1));
            row_idx += 1;
            continue;
        }

        match validar_contra_ac(&nacionalidad, cedula).await {
            Ok(exists) => {
                if !exists {
                    fallidos += 1;
                    detalles.push(format!("Fila {}: Cédula {}-{} no existe en AC", row_idx + 1, nacionalidad, cedula));
                    row_idx += 1;
                    continue;
                }
            }
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error validando en AC: {}", row_idx + 1, e));
                row_idx += 1;
                continue;
            }
        }

        // ✅ Bloquear duplicado por cédula
        match existe_usuario_por_cedula(&app_state, &nacionalidad, cedula).await {
            Ok(true) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Ya existe un usuario con {}-{} (duplicado)", row_idx + 1, nacionalidad, cedula));
                row_idx += 1;
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error verificando duplicado: {}", row_idx + 1, e));
                row_idx += 1;
                continue;
            }
        }

        let login = generar_login(&nombre, &apellido, cedula);
        let password = generar_password(&nombre, &apellido, cedula);
        let hashed_password = format!("{:x}", Sha256::digest(password.as_bytes()));

        let tx_result = sqlx::query(
            r#"
            INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (login) DO NOTHING
            RETURNING id
            "#
        )
        .bind(&nacionalidad)
        .bind(cedula)
        .bind(&nombre)
        .bind(&apellido)
        .bind(&login)
        .bind(&hashed_password)
        .bind(activo)
        .bind(expired)
        .fetch_optional(&app_state.pool_pg)
        .await;

        match tx_result {
            Ok(Some(_)) => {
                if let Ok(user_id) = sqlx::query_scalar::<_, i32>(
                    "SELECT id FROM usuario WHERE login = $1"
                )
                .bind(&login)
                .fetch_one(&app_state.pool_pg)
                .await
                {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO rol_usuario (id_rol, id_usuario) VALUES ($1, $2)
                        ON CONFLICT (id_usuario) DO UPDATE SET id_rol = $1
                        "#
                    )
                    .bind(id_rol)
                    .bind(user_id)
                    .execute(&app_state.pool_pg)
                    .await;

                    exitosos += 1;
                    detalles.push(format!("Fila {}: Usuario {} creado exitosamente (login: {})", row_idx + 1, nombre, login));
                } else {
                    fallidos += 1;
                    detalles.push(format!("Fila {}: No se pudo obtener ID del usuario {}", row_idx + 1, nombre));
                }
            }
            Ok(None) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Login '{}' ya existe (usuario duplicado)", row_idx + 1, login));
            }
            Err(e) => {
                fallidos += 1;
                detalles.push(format!("Fila {}: Error creando usuario {}: {}", row_idx + 1, nombre, e));
            }
        }

        row_idx += 1;
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles })
}