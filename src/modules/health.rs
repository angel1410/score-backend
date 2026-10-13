// src/modules/health.rs
use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::time::Instant;

use crate::structs::AppState;

static SERVER_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

#[derive(Serialize)]
pub struct ServiceHealth {
    pub status: String,
    pub latency_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct HealthStatusResponse {
    pub status: String, // "healthy", "degraded", "down"
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub postgresql: ServiceHealth,
    pub oracle: ServiceHealth,
    pub version: String,
}

pub async fn get_health_status(app_state: web::Data<AppState>) -> impl Responder {
    let uptime_seconds = SERVER_START_TIME.elapsed().as_secs();
    let timestamp = Utc::now().to_rfc3339();

    // 1. Verificar PostgreSQL
    let pg_start = Instant::now();
    let pg_result = sqlx::query("SELECT 1")
        .execute(&app_state.pool_pg)
        .await;

    let pg_health = match pg_result {
        Ok(_) => ServiceHealth {
            status: "connected".to_string(),
            latency_ms: pg_start.elapsed().as_millis(),
            error: None,
        },
        Err(e) => ServiceHealth {
            status: "disconnected".to_string(),
            latency_ms: pg_start.elapsed().as_millis(),
            error: Some(e.to_string()),
        },
    };

    // 2. Consultar versión desde parámetros de PostgreSQL
    let version_query = sqlx::query_scalar::<_, String>(
        "SELECT p_text FROM parametros WHERE nombre_parametro = 'version' LIMIT 1",
    )
    .fetch_optional(&app_state.pool_pg)
    .await;

    let version = version_query
        .ok()
        .flatten()
        .unwrap_or_else(|| "5.0".to_string());

    // 3. Verificar Oracle de forma no bloqueante
    let oracle_pool = app_state.pool_oracle.clone();
    let oracle_health = tokio::task::spawn_blocking(move || {
        let oracle_start = Instant::now();
        match oracle_pool.get() {
            Ok(conn) => {
                match conn.query_row("SELECT 1 FROM DUAL", &[]) {
                    Ok(_) => ServiceHealth {
                        status: "connected".to_string(),
                        latency_ms: oracle_start.elapsed().as_millis(),
                        error: None,
                    },
                    Err(e) => ServiceHealth {
                        status: "error".to_string(),
                        latency_ms: oracle_start.elapsed().as_millis(),
                        error: Some(e.to_string()),
                    },
                }
            }
            Err(e) => ServiceHealth {
                status: "pool_exhausted_or_disconnected".to_string(),
                latency_ms: oracle_start.elapsed().as_millis(),
                error: Some(e.to_string()),
            },
        }
    })
    .await
    .unwrap_or_else(|e| ServiceHealth {
        status: "task_panic".to_string(),
        latency_ms: 0,
        error: Some(e.to_string()),
    });

    let is_pg_ok = pg_health.status == "connected";
    let is_oracle_ok = oracle_health.status == "connected";

    let (overall_status, mut http_status) = if is_pg_ok && is_oracle_ok {
        ("healthy", HttpResponse::Ok())
    } else if is_pg_ok {
        ("degraded", HttpResponse::Ok())
    } else {
        ("down", HttpResponse::ServiceUnavailable())
    };

    let response = HealthStatusResponse {
        status: overall_status.to_string(),
        timestamp,
        uptime_seconds,
        postgresql: pg_health,
        oracle: oracle_health,
        version,
    };

    http_status.json(response)
}
