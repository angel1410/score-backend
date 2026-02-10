use actix_web::{web, HttpResponse, Responder};
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use log;
use rand::Rng;
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

fn generar_login(nombre: &str, apellido: &str, cedula: i32) -> String {
    // ✅ CORREGIDO: inicial nombre + apellido COMPLETO + cedula
    let inicial_nombre = nombre
        .chars()
        .next()
        .map(|c| c.to_lowercase().to_string())
        .unwrap_or_default();
    
    let apellido_limpio = apellido.trim().to_lowercase();
    
    format!("{}{}{}", inicial_nombre, apellido_limpio, cedula)
}

fn generar_password() -> String {
    const CARACTERES: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..8).map(|_| {
        let idx = rng.gen_range(0..CARACTERES.len());
        CARACTERES[idx] as char
    }).collect()
}

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

pub async fn crear_usuario(
    app_state: web::Data<AppState>,
    usuario: web::Json<UsuarioCreate>,
) -> impl Responder {
    let login = generar_login(&usuario.nombre, &usuario.apellido, usuario.cedula);
    let password_generada = generar_password();
    let hashed_password = format!("{:x}", Sha256::digest(password_generada.as_bytes()));

    let user = match sqlx::query_as::<_, Usuario>(
        "INSERT INTO usuario (nacionalidad, cedula, nombre, apellido, login, password, activo, expired) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
    )
    .bind(&usuario.nacionalidad)
    .bind(usuario.cedula)
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

    HttpResponse::Created().json(UsuarioConPassword {
        usuario: user,
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
        "SELECT id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired 
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
         RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
    )
    .bind(&password_to_use)
    .bind(usuario.activo)
    .bind(usuario.expired)
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
         WHERE id = $1 RETURNING id, nacionalidad, cedula, nombre, apellido, login, password, activo, expired"
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

// ✅ Carga masiva deshabilitada temporalmente (sin imports innecesarios)
pub async fn carga_masiva(
    _app_state: web::Data<AppState>,
    _payload: actix_multipart::Multipart,
) -> impl Responder {
    HttpResponse::NotImplemented().body("Carga masiva deshabilitada temporalmente")
}