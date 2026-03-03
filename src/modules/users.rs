// src/modules/users.rs
use actix_web::{web, HttpResponse, Responder, Error};
use actix_multipart::Multipart;
use sqlx::FromRow;
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

// ✅ Estructura Usuario para operaciones CRUD (sin nombre_rol)
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
// ✅ AGREGAR FromRow aquí
#[derive(FromRow, Serialize, Deserialize, Debug, Clone)]
pub struct UsuarioConRol {
    pub id: i32,
    pub id_rol: i32,
    pub nombre_rol: String,      // ✅ Viene del JOIN con roles
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

// ✅ Resultado de carga masiva
#[derive(Serialize)]
pub struct CargaMasivaResultado {
    pub exitosos: usize,
    pub fallidos: usize,
    pub detalles: Vec<String>,
}

// ✅ Respuesta de error
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
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

// ✅ LISTAR todos los usuarios CON nombre_rol
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

// ✅ CREAR usuario nuevo
pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    let nacionalidad = usuario.nacionalidad.trim().to_uppercase();
    let cedula = usuario.cedula;

    // Validar nacionalidad
    if !(nacionalidad == "V" || nacionalidad == "E") {
        return HttpResponse::BadRequest().body("nacionalidad debe ser V o E");
    }

    // Validar cédula
    if cedula <= 0 || cedula > 99_999_999 {
        return HttpResponse::BadRequest().body("cedula inválida");
    }

    // Validar duplicado por cédula
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

    // Generar username y password
    let username = generar_username(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let password_generada = generar_password(&usuario.primer_nombre, &usuario.primer_apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password_generada.as_bytes()));

    // Insertar en tabla usuarios (id_rol directo, sin rol_usuario)
    let user = match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira, id_rol) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
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

    HttpResponse::Created().json(UsuarioConPassword {
        usuario: user,
        password_generada,
    })
}

// ✅ ACTUALIZAR usuario existente
pub async fn actualizar_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
    usuario: web::Json<UsuarioUpdate>,
) -> impl Responder {
    let user_id = id.into_inner();

    // Verificar que existe
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

    // Usar password existente o nueva
    let password_to_use = match &usuario.password {
        Some(p) if !p.trim().is_empty() => format!("{:x}", Sha256::digest(p.as_bytes())),
        _ => existing_user.password,
    };

    // Actualizar usuario (id_rol directo, sin rol_usuario)
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

    HttpResponse::Ok().json(updated_user)
}

// ✅ BLOQUEAR/ACTIVAR usuario (toggle)
pub async fn bloquear_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
) -> impl Responder {
    let user_id = id.into_inner();

    match sqlx::query_as::<_, Usuario>(
        "UPDATE usuarios SET activo = NOT activo
         WHERE id = $1 
         RETURNING id, id_rol, nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira"
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

// ✅ ELIMINAR usuario (sin rol_usuario, más simple)
pub async fn eliminar_usuario(
    app_state: web::Data<AppState>,
    id: web::Path<i32>,
) -> impl Responder {
    let user_id = id.into_inner();

    // Verificar existencia
    let exists = match sqlx::query_scalar::<_, i32>("SELECT 1 FROM usuarios WHERE id = $1")
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

    // ✅ Eliminar directo (ya no hay rol_usuario)
    match sqlx::query("DELETE FROM usuarios WHERE id = $1")
        .bind(user_id)
        .execute(&app_state.pool_pg)
        .await
    {
        Ok(_) => HttpResponse::Ok().body("Usuario eliminado"),
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

// ====== CARGA MASIVA ======
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

// ✅ Procesar CSV
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

        // ✅ 6 columnas esperadas
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

        // ✅ Valores por defecto
        let id_rol = 2;
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
        ).await;
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles })
}

// ✅ Procesar Excel XLSX
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

// ✅ Procesar Excel XLS
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

// ✅ Procesar rango de Excel
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

        // ✅ Validar 6 columnas
        if row.len() < 6 {
            fallidos += 1;
            detalles.push(format!("Fila {}: Columnas insuficientes (se esperan 6)", row_idx + 1));
            row_idx += 1;
            continue;
        }

        // ✅ Leer 6 columnas
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

        // ✅ Valores por defecto
        let id_rol = 2;
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
        ).await;

        row_idx += 1;
    }

    Ok(CargaMasivaResultado { exitosos, fallidos, detalles })
}

// ✅ Función común para procesar cada fila
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
) {
    // ✅ Validar datos requeridos
    if nacionalidad.is_empty() || cedula == 0 || primer_nombre.is_empty() || primer_apellido.is_empty() {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Datos incompletos", fila));
        return;
    }

    // ✅ Validar nacionalidad
    if !(nacionalidad == "V" || nacionalidad == "E") {
        *fallidos += 1;
        detalles.push(format!("Fila {}: Nacionalidad inválida (debe ser V o E)", fila));
        return;
    }

    // ✅ Validar contra Oracle (AC)
    match validar_contra_ac(&nacionalidad, cedula).await {
        Ok(exists) => {
            if !exists {
                *fallidos += 1;
                detalles.push(format!("Fila {}: Cédula {}-{} no existe en AC", fila, nacionalidad, cedula));
                return;
            }
        }
        Err(e) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Error validando en AC: {}", fila, e));
            return;
        }
    }

    // ✅ Bloquear duplicado por cédula
    match existe_usuario_por_cedula(&app_state, &nacionalidad, cedula).await {
        Ok(true) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Ya existe un usuario con {}-{} (duplicado)", fila, nacionalidad, cedula));
            return;
        }
        Ok(false) => {}
        Err(e) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Error verificando duplicado: {}", fila, e));
            return;
        }
    }

    // ✅ Generar username y password
    let username = generar_username(&primer_nombre, &primer_apellido, cedula);
    let password = generar_password(&primer_nombre, &primer_apellido, cedula);
    let hashed_password = format!("{:x}", Sha256::digest(password.as_bytes()));

    // ✅ Insertar en tabla usuarios
    let tx_result = sqlx::query(
        r#"
        INSERT INTO usuarios (nacionalidad, cedula, primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, username, password, activo, expira, id_rol) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (username) DO NOTHING
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

    match tx_result {
        Ok(Some(_)) => {
            *exitosos += 1;
            detalles.push(format!("Fila {}: Usuario {} {} creado exitosamente (username: {})", fila, primer_nombre, primer_apellido, username));
        }
        Ok(None) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Username '{}' ya existe (usuario duplicado)", fila, username));
        }
        Err(e) => {
            *fallidos += 1;
            detalles.push(format!("Fila {}: Error creando usuario {}: {}", fila, primer_nombre, e));
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