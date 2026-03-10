// src/modules/security.rs
use actix_web::{web, HttpResponse, Responder};
use chrono::{Utc, Duration};
use serde::Serialize;
use sqlx::FromRow;
use crate::structs::AppState;

#[derive(Serialize, FromRow, Debug)]
pub struct IpActivity {
    pub ip: String,
    pub intentos: i64,
    pub ultimo_intento: chrono::NaiveDateTime,
}

#[derive(Serialize, FromRow, Debug)]
pub struct HourlyActivity {
    pub hora: String,
    pub exitosos: i64,
    pub fallidos: i64,
}

pub async fn get_security_dashboard(
    app_state: web::Data<AppState>,
) -> impl Responder {
    let now = Utc::now();
    let since = now - Duration::hours(24);

    // ✅ CONSULTA 1: Estadísticas generales
    let stats_result = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        r#"
        SELECT 
            COUNT(*)::bigint,
            COUNT(*) FILTER (WHERE accion = 'INICIO DE SESIÓN')::bigint,
            COUNT(*) FILTER (WHERE accion != 'INICIO DE SESIÓN')::bigint,
            0::bigint
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 1
        "#
    )
    .bind(since)
    .fetch_one(&app_state.pool_pg)
    .await;

    let (total, exitosos, fallidos, _alertas) = match stats_result {
        Ok(row) => row,
        Err(_) => (0, 0, 0, 0),
    };

    // ✅ CONSULTA 2: Actividad por hora
    let actividad = sqlx::query_as::<_, HourlyActivity>(
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
        "#
    )
    .bind(since)
    .fetch_all(&app_state.pool_pg)
    .await
    .unwrap_or_default();

    // ✅ CONSULTA 3: Top IPs
    let top_ips = sqlx::query_as::<_, IpActivity>(
        r#"
        SELECT 
            ip_origen as ip,
            COUNT(*)::bigint as intentos,
            MAX(created_at) as ultimo_intento
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 1
        GROUP BY ip_origen 
        ORDER BY intentos DESC 
        LIMIT 10
        "#
    )
    .bind(since)
    .fetch_all(&app_state.pool_pg)
    .await  
    .unwrap_or_default();

    // ✅ CONSULTA 4: Honeypot (id_tipo_accion=4, id_accion=15)
    let honeypot_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) 
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 4 
            AND id_accion = 15
        "#
    )
    .bind(since)
    .fetch_one(&app_state.pool_pg)
    .await
    .unwrap_or(0);

    // ✅ CONSULTA 5: Rate Limit (id_tipo_accion=4, id_accion=17)
    let rate_limit_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) 
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 4 
            AND id_accion = 17
        "#
    )
    .bind(since)
    .fetch_one(&app_state.pool_pg)
    .await
    .unwrap_or(0);

    // ✅ CONSULTA 6: CAPTCHA Inválido (id_tipo_accion=4, id_accion=16)
    let captcha_invalid_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) 
        FROM logs 
        WHERE created_at >= $1 
            AND id_tipo_accion = 4 
            AND id_accion = 16
        "#
    )
    .bind(since)
    .fetch_one(&app_state.pool_pg)
    .await
    .unwrap_or(0);

    // ✅ Respuesta JSON
    let response = serde_json::json!({
        "total_logins_24h": total,
        "logins_exitosos_24h": exitosos,
        "logins_fallidos_24h": fallidos,
        "alertas_criticas_24h": _alertas,
        "honeypot_triggered_24h": honeypot_count,
        "rate_limit_exceeded_24h": rate_limit_count,
        "captcha_invalid_24h": captcha_invalid_count,
        "top_ips_sospechosas": top_ips,
        "actividad_por_hora": actividad,
        "timestamp": now,
    });

    log::info!("📊 Dashboard: total={}, exitosos={}, fallidos={}", total, exitosos, fallidos);

    HttpResponse::Ok().json(response)
}