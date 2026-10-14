use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::middleware::auth::is_sistemas;
use crate::structs::AppState;

#[derive(Serialize, FromRow, Debug)]
pub struct IpActivity {
    pub ip: String,
    pub intentos: i64,
    pub ultimo_intento: chrono::NaiveDateTime,
    pub eventos: Option<String>,
}

#[derive(Serialize, FromRow, Debug)]
pub struct HourlyActivity {
    pub hora: String,
    pub exitosos: i64,
    pub fallidos: i64,
}

#[derive(Serialize, FromRow, Debug, Clone)]
pub struct CapsuleIpDetail {
    pub ip: String,
    pub intentos: i64,
    pub ultimo_intento: chrono::NaiveDateTime,
    pub eventos: Option<String>,
    pub cedulas: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Deserialize)]
pub struct CapsulaIpsQuery {
    pub categoria: String,
}

pub async fn get_security_dashboard(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if !is_sistemas(&req) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "No tiene permisos para realizar esta acción"
        }));
    }

    let now = Utc::now();
    let since = now - Duration::hours(24);

    let pool = &app_state.pool_pg;

    let stats_future = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        r#"
        SELECT 
            COUNT(*) FILTER (WHERE id_tipo_accion = 1)::bigint,
            COUNT(*) FILTER (WHERE id_tipo_accion = 1 AND accion = 'INICIO DE SESIÓN')::bigint,
            COUNT(*) FILTER (WHERE id_tipo_accion = 1 AND accion != 'INICIO DE SESIÓN')::bigint,
            COUNT(*) FILTER (WHERE (id_tipo_accion = 4 AND id_accion IN (15, 17)) OR id_accion = 6)::bigint
        FROM logs 
        WHERE created_at >= $1
        "#,
    )
    .bind(since)
    .fetch_one(pool);

    let actividad_future = sqlx::query_as::<_, HourlyActivity>(
        r#"
        SELECT 
            TO_CHAR(created_at, 'HH24:00') as hora,
            COUNT(*) FILTER (WHERE accion = 'INICIO DE SESIÓN')::bigint as exitosos,
            COUNT(*) FILTER (WHERE accion != 'INICIO DE SESIÓN')::bigint as fallidos
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 1
        GROUP BY TO_CHAR(created_at, 'HH24:00')
        ORDER BY hora
        "#,
    )
    .bind(since)
    .fetch_all(pool);

    let top_ips_future = sqlx::query_as::<_, IpActivity>(
        r#"
        SELECT 
            ip_origen as ip,
            COUNT(*)::bigint as intentos,
            MAX(created_at) as ultimo_intento,
            STRING_AGG(DISTINCT accion, ', ') as eventos
        FROM logs 
        WHERE created_at >= $1 
            AND (id_tipo_accion IN (1, 4) OR id_accion = 6)
        GROUP BY ip_origen 
        ORDER BY intentos DESC 
        LIMIT 10
        "#,
    )
    .bind(since)
    .fetch_all(pool);

    let eventos_tipo4_future = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT 
            COUNT(*) FILTER (WHERE id_accion = 15)::bigint,
            COUNT(*) FILTER (WHERE id_accion = 17)::bigint,
            COUNT(*) FILTER (WHERE id_accion = 16)::bigint
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 4
        "#,
    )
    .bind(since)
    .fetch_one(pool);

    // ✅ Ejecutar todas las consultas en paralelo
    let (stats_result, actividad_result, top_ips_result, eventos_tipo4_result) =
        tokio::join!(stats_future, actividad_future, top_ips_future, eventos_tipo4_future);

    let (total, exitosos, fallidos, alertas) = stats_result.unwrap_or((0, 0, 0, 0));
    let actividad = actividad_result.unwrap_or_default();
    let top_ips = top_ips_result.unwrap_or_default();
    let (honeypot_count, rate_limit_count, captcha_invalid_count) =
        eventos_tipo4_result.unwrap_or((0, 0, 0));

    let response = serde_json::json!({
        "total_logins_24h": total,
        "logins_exitosos_24h": exitosos,
        "logins_fallidos_24h": fallidos,
        "alertas_criticas_24h": alertas,
        "honeypot_triggered_24h": honeypot_count,
        "rate_limit_exceeded_24h": rate_limit_count,
        "captcha_invalid_24h": captcha_invalid_count,
        "top_ips_sospechosas": top_ips,
        "actividad_por_hora": actividad,
        "timestamp": now,
    });

    log::info!(
        "📊 Dashboard seguridad: total={}, exitosos={}, fallidos={}, alertas={}",
        total,
        exitosos,
        fallidos,
        alertas
    );

    HttpResponse::Ok().json(response)
}

/// Obtiene el detalle de IPs asociadas a una cápsula específica del dashboard
pub async fn get_capsula_ips(
    req: HttpRequest,
    query: web::Query<CapsulaIpsQuery>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if !is_sistemas(&req) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "No tiene permisos para realizar esta acción"
        }));
    }

    let now = Utc::now();
    let since = now - Duration::hours(24);
    let pool = &app_state.pool_pg;

    let (filter_clause, titulo) = match query.categoria.as_str() {
        "total_logins" => ("id_tipo_accion = 1", "Total Logins (24h)"),
        "logins_exitosos" => (
            "id_tipo_accion = 1 AND accion = 'INICIO DE SESIÓN'",
            "Logins Exitosos",
        ),
        "logins_fallidos" => (
            "id_tipo_accion = 1 AND accion != 'INICIO DE SESIÓN'",
            "Logins Fallidos",
        ),
        "alertas_criticas" => (
            "(id_tipo_accion = 4 AND id_accion IN (15, 17)) OR id_accion = 6",
            "Alertas Críticas y Bloqueos",
        ),
        "honeypot" => (
            "id_tipo_accion = 4 AND id_accion = 15",
            "Honeypot Activado (Trampa de Bots)",
        ),
        "rate_limit" => (
            "id_tipo_accion = 4 AND id_accion = 17",
            "Rate Limit Excedido",
        ),
        "captcha_invalid" => (
            "id_tipo_accion = 4 AND id_accion = 16",
            "CAPTCHA Inválido",
        ),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Categoría de cápsula inválida"
            }));
        }
    };

    let sql = format!(
        r#"
        SELECT 
            ip_origen as ip,
            COUNT(*)::bigint as intentos,
            MAX(created_at) as ultimo_intento,
            STRING_AGG(DISTINCT accion, ', ') as eventos,
            STRING_AGG(DISTINCT cedula_relacionada::text, ', ') FILTER (WHERE cedula_relacionada IS NOT NULL) as cedulas,
            MAX(user_agent) as user_agent
        FROM logs 
        WHERE created_at >= $1 AND {}
        GROUP BY ip_origen 
        ORDER BY intentos DESC, ultimo_intento DESC 
        LIMIT 100
        "#,
        filter_clause
    );

    match sqlx::query_as::<_, CapsuleIpDetail>(&sql)
        .bind(since)
        .fetch_all(pool)
        .await
    {
        Ok(ips) => HttpResponse::Ok().json(serde_json::json!({
            "categoria": query.categoria,
            "titulo": titulo,
            "total_ips": ips.len(),
            "ips": ips,
            "timestamp": now,
        })),
        Err(e) => {
            log::error!("Error consultando IPs de cápsula {}: {}", query.categoria, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Error consultando detalle de IPs",
                "details": e.to_string()
            }))
        }
    }
}