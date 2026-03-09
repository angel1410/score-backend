// src/modules/parametros.rs
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use crate::structs::AppState;

// ✅ ESTRUCTURAS
#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct Parametro {
    pub id: i32,
    pub nombre_parametro: String,
    pub descripcion_parametro: Option<String>,
    pub p_boolean: Option<bool>,
    pub p_integer: Option<i32>,
    pub p_text: Option<String>,
    pub p_date: Option<chrono::NaiveDate>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Deserialize, Debug)]
pub struct ParametroCreate {
    pub nombre_parametro: String,
    pub descripcion_parametro: Option<String>,
    pub p_boolean: Option<bool>,
    pub p_integer: Option<i32>,
    pub p_text: Option<String>,
    pub p_date: Option<chrono::NaiveDate>,
}

#[derive(Deserialize, Debug)]
pub struct ParametroUpdate {
    pub descripcion_parametro: Option<String>,
    pub p_boolean: Option<bool>,
    pub p_integer: Option<i32>,
    pub p_text: Option<String>,
    pub p_date: Option<chrono::NaiveDate>,
}

// ✅ CRUD
pub async fn get_parametros(app_state: web::Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, Parametro>(
        "SELECT * FROM parametros ORDER BY nombre_parametro ASC"
    )
    .fetch_all(&app_state.pool_pg)
    .await
    {
        Ok(parametros) => HttpResponse::Ok().json(parametros),
        Err(e) => {
            log::error!("Error obteniendo parámetros: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo parámetros",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn get_parametro_by_nombre(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let nombre = path.into_inner();
    
    match sqlx::query_as::<_, Parametro>(
        "SELECT * FROM parametros WHERE nombre_parametro = $1"
    )
    .bind(&nombre)
    .fetch_optional(&app_state.pool_pg)
    .await
    {
        Ok(Some(parametro)) => HttpResponse::Ok().json(parametro),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("Parámetro '{}' no encontrado", nombre)
        })),
        Err(e) => {
            log::error!("Error obteniendo parámetro: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo parámetro",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn crear_parametro(
    app_state: web::Data<AppState>,
    parametro: web::Json<ParametroCreate>,
) -> impl Responder {
    match sqlx::query_as::<_, Parametro>(
        r#"
        INSERT INTO parametros (nombre_parametro, descripcion_parametro, p_boolean, p_integer, p_text, p_date)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#
    )
    .bind(&parametro.nombre_parametro)
    .bind(&parametro.descripcion_parametro)
    .bind(&parametro.p_boolean)
    .bind(&parametro.p_integer)
    .bind(&parametro.p_text)
    .bind(&parametro.p_date)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(p) => HttpResponse::Created().json(p),
        Err(e) => {
            log::error!("Error creando parámetro: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error creando parámetro",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn actualizar_parametro(
    app_state: web::Data<AppState>,
    path: web::Path<i32>,
    parametro: web::Json<ParametroUpdate>,
) -> impl Responder {
    let id = path.into_inner();
    
    match sqlx::query_as::<_, Parametro>(
        r#"
        UPDATE parametros 
        SET descripcion_parametro = COALESCE($1, descripcion_parametro),
            p_boolean = COALESCE($2, p_boolean),
            p_integer = COALESCE($3, p_integer),
            p_text = COALESCE($4, p_text),
            p_date = COALESCE($5, p_date)
        WHERE id = $6
        RETURNING *
        "#
    )
    .bind(&parametro.descripcion_parametro)
    .bind(&parametro.p_boolean)
    .bind(&parametro.p_integer)
    .bind(&parametro.p_text)
    .bind(&parametro.p_date)
    .bind(id)
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(p) => HttpResponse::Ok().json(p),
        Err(e) => {
            log::error!("Error actualizando parámetro: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error actualizando parámetro",
                "details": e.to_string()
            }))
        }
    }
}

pub async fn eliminar_parametro(
    app_state: web::Data<AppState>,
    path: web::Path<i32>,
) -> impl Responder {
    let id = path.into_inner();
    
    match sqlx::query("DELETE FROM parametros WHERE id = $1")
        .bind(id)
        .execute(&app_state.pool_pg)
        .await
    {
        Ok(_) => HttpResponse::Ok().body("Parámetro eliminado"),
        Err(e) => {
            log::error!("Error eliminando parámetro: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error eliminando parámetro",
                "details": e.to_string()
            }))
        }
    }
}

// ✅ FUNCIÓN ESPECIAL: Obtener fecha_cierre
pub async fn get_fecha_cierre(app_state: web::Data<AppState>) -> impl Responder {
    match sqlx::query_scalar::<_, Option<chrono::NaiveDate>>(
        "SELECT p_date FROM parametros WHERE nombre_parametro = 'fecha_cierre'"
    )
    .fetch_one(&app_state.pool_pg)
    .await
    {
        Ok(Some(fecha)) => HttpResponse::Ok().json(serde_json::json!({
            "fecha_cierre": fecha
        })),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "fecha_cierre": null,
            "mensaje": "No hay fecha de cierre configurada"
        })),
        Err(e) => {
            log::error!("Error obteniendo fecha_cierre: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error obteniendo fecha_cierre",
                "details": e.to_string()
            }))
        }
    }
}