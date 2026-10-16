#![allow(dead_code)]
use actix_web::{web, Error, HttpRequest, HttpResponse};
use oracle::{Row, RowValue};
use serde::Deserialize;
use sqlx::Row as SqlxRow;
use std::time::Instant;

use crate::middleware::auth::{
    get_current_user_id, is_operador, require_consulta_basica, require_consulta_completa,
};
use crate::modules::logging::LogEntry;
use crate::structs::AppState;

// =====================
// Helper Functions para Logging
// =====================

fn log_movimientos_re_entry(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 10,
        id_usuario: Some(usuario_id),
        accion: "MOVIMIENTOS RE".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

fn log_consultar_datos_elector_entry(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 14,
        id_usuario: Some(usuario_id),
        accion: "CONSULTAR DATOS ELECTOR".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

fn log_votos_emitir_entry(usuario_id: i32, cedula_elector: i32, ip: String, ua: String) -> LogEntry {
    LogEntry {
        id_tipo_accion: 3,
        id_accion: 11,
        id_usuario: Some(usuario_id),
        accion: "VOTOS A EMITIR".to_string(),
        cedula_relacionada: Some(cedula_elector),
        ip_origen: ip,
        user_agent: ua,
    }
}

fn get_autor_id(req: &HttpRequest) -> Option<i32> {
    get_current_user_id(req).ok()
}

#[derive(serde::Serialize)]
struct MovimientoRE {
    CIERRE: i32,
    NOMBRE_CORTO: Option<String>,
    ID_LOTE: i32,
    DESCRIPCION_MOVIMIENTO: String,
    DESCRIPCION_STATUS: String,
    FECHA_PROCESO_MOV: String,
}

impl RowValue for MovimientoRE {
    fn get(row: &Row) -> std::result::Result<MovimientoRE, oracle::Error> {
        Ok(MovimientoRE {
            CIERRE: row.get("CIERRE")?,
            NOMBRE_CORTO: row.get("NOMBRE_CORTO")?,
            ID_LOTE: row.get("ID_LOTE")?,
            DESCRIPCION_MOVIMIENTO: row.get("DESCRIPCION_MOVIMIENTO")?,
            DESCRIPCION_STATUS: row.get("DESCRIPCION_STATUS")?,
            FECHA_PROCESO_MOV: row.get("FECHA_PROCESO_MOV")?,
        })
    }
}

// =====================
// Movimiento RE
// =====================

pub async fn get_movimientos_re(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    use crate::modules::logging::registrar_log;

    if let Err(res) = require_consulta_basica(&req) {
        return Ok(res);
    }

    let (nacionalidad, cedula_str) = path.into_inner();
    let nacionalidad = nacionalidad.to_uppercase();
    let cedula_int: i32 = cedula_str
        .parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("Cédula inválida"))?;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nacionalidad inválida"));
    }

    let pool_oracle = app_state.pool_oracle.clone();
    let nac_clone = nacionalidad.clone();

    let re_array = web::block(move || -> Result<Vec<MovimientoRE>, String> {
        let conn = pool_oracle.get().map_err(|e| {
            log::error!("❌ Error obteniendo conexión de Oracle Pool: {}", e);
            e.to_string()
        })?;

        let sql = "SELECT
            t.CIERRE, c.NOMBRE_CORTO, t.ID_LOTE, tm.DESCRIPCION DESCRIPCION_MOVIMIENTO,
            spm.descripcion DESCRIPCION_STATUS, t.FECHA_PROCESO_MOV
            from re.movimiento t
            left join re.cierre c
            on t.cierre=c.codigo
            left join re.tipo_movimiento tm
            on t.tipo_movimiento=tm.tipo_movimiento
            left join re.status_proceso_mov spm
            on t.status_proceso_mov=spm.codigo
            where t.nacionalidad= :nacionalidad
            And T.Cedula_Number= :cedula
            order by cierre desc";

        let rows = conn
            .query_as::<MovimientoRE>(sql, &[&nac_clone, &cedula_int])
            .map_err(|e| {
                log::error!("❌ Error ejecutando query: {}", e);
                e.to_string()
            })?;

        let mut re_array: Vec<MovimientoRE> = Vec::new();
        for row_result in rows {
            let mov = row_result.map_err(|e| {
                log::error!("❌ Error procesando fila: {}", e);
                e.to_string()
            })?;
            re_array.push(mov);
        }

        Ok(re_array)
    })
    .await
    .map_err(|e| {
        log::error!("❌ Error en blocking task movimientos: {}", e);
        actix_web::error::ErrorInternalServerError("Error interno del servidor")
    })?
    .map_err(|_| actix_web::error::ErrorInternalServerError("Error interno del servidor"))?;

    if let Some(autor_id) = get_autor_id(&req) {
        let ip_origen = crate::modules::logging::extract_ip(&req);
        let user_agent = crate::modules::logging::extract_user_agent(&req);
        let log_entry = log_movimientos_re_entry(autor_id, cedula_int, ip_origen, user_agent);
        let pool_clone = app_state.pool_pg.clone();
        tokio::spawn(async move {
            let _ = registrar_log(&pool_clone, log_entry).await;
        });
    }

    Ok(HttpResponse::Ok().json(&re_array))
}

// =====================
// Elector
// =====================

#[derive(Deserialize)]
pub struct ElectorQuery {
    pub nacionalidad: String,
    pub cedula: i64,
}

#[derive(serde::Serialize, Default)]
pub struct ElectorResponse {
    pub nacionalidad: String,
    pub cedula: i64,
    pub fecha_nacimiento: Option<String>,
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub codigo_objecion: Option<String>,
    pub descripcion_objecion: Option<String>,
    pub direccion_elector: Option<String>,
    pub fecha_ultimo_evento: Option<String>,
    pub edad_ultimo_evento: Option<i64>,
    pub numero_mesa: Option<i64>,
    pub numero_pagina: Option<i64>,
    pub numero_renglon: Option<i64>,
    pub codigo_centro: Option<String>,
    pub estado: Option<String>,
    pub municipio: Option<String>,
    pub parroquia: Option<String>,
    pub nombre_centro: Option<String>,
    pub direccion_centro: Option<String>,
    pub estado_actual: Option<String>,
    pub municipio_actual: Option<String>,
    pub parroquia_actual: Option<String>,
    pub codigo_centro_actual: Option<String>,
    pub nombre_centro_actual: Option<String>,
    pub direccion_centro_actual: Option<String>,
    pub miembro_mesa_es_miembro: Option<bool>,
    pub miembro_mesa_organismo: Option<String>,
    pub miembro_mesa_cargo: Option<String>,
    pub miembro_mesa_numero_mesa: Option<i64>,
    pub miembro_mesa_codigo_mesa: Option<i64>,
    pub miembro_mesa_mesa_electoral: Option<i64>,
    pub miembro_mesa_tipo_sorteo: Option<i64>,
    pub miembro_mesa_codigo_centro: Option<String>,
}

fn yyyymmdd_to_iso(s: &str) -> Option<String> {
    if s.len() < 8 {
        return None;
    }
    Some(format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]))
}

fn pad9(n: i64) -> String {
    format!("{:09}", n)
}

fn normalize_codigo_centro_9<S: AsRef<str>>(s: S) -> Option<String> {
    let trimmed = s.as_ref().trim();
    if trimmed.is_empty() {
        return None;
    }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse::<i64>().ok()?;
    Some(format!("{:09}", value))
}

fn clean_geo_desc(s: String) -> String {
    let mut t = s.trim().to_string();
    let upper = t.to_uppercase();
    let prefixes = [
        "EDO.", "EDO", "ESTADO", "MP.", "MP", "MUN.", "MUN", "MUNICIPIO", "PQ.", "PQ", "PAR.",
        "PAR", "PARROQUIA",
    ];
    for p in prefixes.iter() {
        if upper.starts_with(p) {
            t = t[p.len()..].trim().to_string();
            break;
        }
    }
    t = t
        .trim_start_matches(|c: char| c == '-' || c == '—' || c == ':')
        .trim()
        .to_string();
    t
}

fn na(v: Option<String>) -> String {
    let t = v.unwrap_or_default().trim().to_string();
    if t.is_empty() {
        "No aplica".to_string()
    } else {
        t
    }
}

fn build_direccion_elector(
    ciudad: Option<String>,
    urbanizacion: Option<String>,
    sector: Option<String>,
    avenida_calle: Option<String>,
    edificio_casa: Option<String>,
    apartamento: Option<String>,
) -> String {
    format!(
        "CIUDAD: {}, AVENIDA-CALLE: {}, URBANIZACION: {}, SECTOR: {}, EDIFICIO-CASA: {}, APARTAMENTO: {}",
        na(ciudad),
        na(avenida_calle),
        na(urbanizacion),
        na(sector),
        na(edificio_casa),
        na(apartamento),
    )
}

fn fmt_geo(code: i64, desc: Option<String>) -> String {
    let code2 = format!("{:02}", code);
    let d = desc
        .map(clean_geo_desc)
        .unwrap_or_else(|| "NO DEFINIDO".to_string());
    format!("{code2} - {d}")
}

fn fmt_geo_sigla(prefix: &str, desc: Option<String>) -> String {
    let d = desc
        .map(clean_geo_desc)
        .unwrap_or_else(|| "NO DEFINIDO".to_string());
    format!("{prefix} {d}")
}

fn ddmmyyyy(s: &str) -> Option<String> {
    if s.len() < 8 {
        return None;
    }
    Some(format!("{}-{}-{}", &s[0..2], &s[2..4], &s[4..8]))
}

fn fmt_horario(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() >= 12 {
        let a_h = &t[0..2];
        let a_m = &t[2..6];
        let b_h = &t[6..8];
        let b_m = &t[8..12];
        return Some(format!("{a_h}:{a_m}-{b_h}:{b_m}"));
    }
    if t.len() >= 8 {
        let a_h = &t[0..2];
        let a_m = &t[2..4];
        let b_h = &t[4..6];
        let b_m = &t[6..8];
        return Some(format!("{a_h}:{a_m}-{b_h}:{b_m}"));
    }
    None
}

fn set_no_aplica_miembro(resp: &mut ElectorResponse) {
    resp.miembro_mesa_es_miembro = Some(false);
    resp.miembro_mesa_organismo = Some("No aplica".to_string());
    resp.miembro_mesa_cargo = Some("No aplica".to_string());
    resp.miembro_mesa_numero_mesa = None;
    resp.miembro_mesa_codigo_mesa = None;
    resp.miembro_mesa_mesa_electoral = None;
    resp.miembro_mesa_tipo_sorteo = None;
    resp.miembro_mesa_codigo_centro = Some("No aplica".to_string());
}

fn aplicar_filtro_operador(resp: &mut ElectorResponse) {
    resp.direccion_elector = None;
}

pub async fn get_elector(
    query: web::Query<ElectorQuery>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {


    if let Err(res) = require_consulta_basica(&req) {
        return Ok(res);
    }

    let operador = is_operador(&req);

    let nac = query.nacionalidad.trim().to_uppercase();
    let nacionalidad = nac.chars().next().unwrap_or('V').to_string();
    let cedula = query.cedula;
    let cedula_int = cedula as i32;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let pool_oracle = app_state.pool_oracle.clone();
    let nac_clone = nacionalidad.clone();

    let resp_opt = web::block(move || -> Result<Option<ElectorResponse>, String> {
        let conn = pool_oracle.get().map_err(|e| {
            log::error!("❌ Error obteniendo conexión de Oracle Pool: {}", e);
            e.to_string()
        })?;

        let mut resp = ElectorResponse {
            nacionalidad: nac_clone.clone(),
            cedula,
            ..Default::default()
        };

        let sql_persona = r#"
            SELECT AC.PRIMER_APELLIDO, AC.SEGUNDO_APELLIDO, AC.PRIMER_NOMBRE, AC.SEGUNDO_NOMBRE,
            AC.FECHA_NACIMIENTO_4, AC.STATUS_OBJECION, OBJ.DESCRIPCION,
            MD.CIUDAD, MD.URBANIZACION, MD.SECTOR, MD.AVENIDA_CALLE, MD.EDIFICIO_CASA, MD.APARTAMENTO
            FROM AC AC
            JOIN OBJECION OBJ ON AC.STATUS_OBJECION = OBJ.STATUS
            LEFT JOIN RE.MAESTRO_DIRECCION MD ON MD.NACIONALIDAD = AC.NACIONALIDAD AND MD.CEDULA = AC.CEDULA
            WHERE AC.NACIONALIDAD = :nacionalidad AND AC.CEDULA = :cedula
        "#;

        let mut rows = conn.query(sql_persona, &[&nac_clone, &cedula]).map_err(|e| {
            log::error!("❌ Error query persona: {}", e);
            e.to_string()
        })?;

        let row_opt = rows.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo persona: {}", e);
            e.to_string()
        })?;

        let row = match row_opt {
            Some(r) => r,
            None => {
                return Ok(None);
            }
        };

        resp.primer_apellido = row.get(0).ok();
        resp.segundo_apellido = row.get(1).ok();
        resp.primer_nombre = row.get(2).ok();
        resp.segundo_nombre = row.get(3).ok();
        let fecha_raw: Option<String> = row.get(4).ok();
        resp.fecha_nacimiento = fecha_raw.as_deref().and_then(yyyymmdd_to_iso);
        let cod_obj: Option<i64> = row.get(5).ok();
        resp.codigo_objecion = cod_obj.map(|x| x.to_string());
        resp.descripcion_objecion = row.get(6).ok();

        let ciudad: Option<String> = row.get(7).ok();
        let urbanizacion: Option<String> = row.get(8).ok();
        let sector: Option<String> = row.get(9).ok();
        let avenida_calle: Option<String> = row.get(10).ok();
        let edificio_casa: Option<String> = row.get(11).ok();
        let apartamento: Option<String> = row.get(12).ok();

        resp.direccion_elector = Some(build_direccion_elector(
            ciudad, urbanizacion, sector, avenida_calle, edificio_casa, apartamento,
        ));

        let sql_cuaderno = r#"
            SELECT nu_mesa, nu_pagina, nu_renglon, nu_edad_al_evento, fe_evento,
            cod_estado, cod_municipio, cod_parroquia, nu_centro
            FROM instrumentos.cuaderno_actual2
            WHERE co_nacionalidad = :nacionalidad AND nu_cedula = :cedula
        "#;

        let mut rows2 = conn.query(sql_cuaderno, &[&nac_clone, &cedula]).map_err(|e| {
            log::error!("❌ Error query cuaderno: {}", e);
            e.to_string()
        })?;

        let row2_opt = rows2.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo cuaderno: {}", e);
            e.to_string()
        })?;

        let (cod_estado, cod_municipio, cod_parroquia, cod_centro): (Option<i64>, Option<i64>, Option<i64>, Option<i64>) =
            if let Some(r2) = row2_opt {
                resp.numero_mesa = r2.get(0).ok();
                resp.numero_pagina = r2.get(1).ok();
                resp.numero_renglon = r2.get(2).ok();
                resp.edad_ultimo_evento = r2.get(3).ok();
                let fe: Option<String> = r2.get(4).ok();
                resp.fecha_ultimo_evento = fe.map(|x| x.chars().take(10).collect());
                let ce: Option<i64> = r2.get(5).ok();
                let cm: Option<i64> = r2.get(6).ok();
                let cp: Option<i64> = r2.get(7).ok();
                let cc: Option<i64> = r2.get(8).ok();
                resp.codigo_centro = cc.map(pad9);
                (ce, cm, cp, cc)
            } else {
                (None, None, None, None)
            };

        if let (Some(ce), Some(cm), Some(cp), Some(cc)) = (cod_estado, cod_municipio, cod_parroquia, cod_centro) {
            let sql_geo = r#"
                SELECT COD_ESTADO, DES_ESTADO, COD_MUNICIPIO, DES_MUNICIPIO, COD_PARROQUIA,
                DES_PARROQUIA, CODIGO_NUEVO, NOMBRE, DIRECCION
                FROM RE.V_CENTRO_VOTACION_GEOGRAFICO
                WHERE CODIGO_NUEVO = :cc AND COD_ESTADO = :ce AND COD_MUNICIPIO = :cm AND COD_PARROQUIA = :cp
            "#;

            let mut rows3 = conn.query(sql_geo, &[&cc, &ce, &cm, &cp]).map_err(|e| {
                log::error!("❌ Error query vista geografica: {}", e);
                e.to_string()
            })?;

            if let Some(r3) = rows3.next().transpose().map_err(|e| {
                log::error!("❌ Error leyendo vista geografica: {}", e);
                e.to_string()
            })? {
                let des_estado: Option<String> = r3.get(1).ok();
                let des_municipio: Option<String> = r3.get(3).ok();
                let des_parroquia: Option<String> = r3.get(5).ok();
                resp.estado = Some(fmt_geo(ce, des_estado));
                resp.municipio = Some(fmt_geo(cm, des_municipio));
                resp.parroquia = Some(fmt_geo(cp, des_parroquia));
                resp.nombre_centro = r3.get(7).ok();
                resp.direccion_centro = r3.get(8).ok();
            }
        }

        let sql_centro_actual = r#"
            SELECT
                TO_CHAR(ccv.codigo_nuevo) AS codigo_nuevo,
                cv.estado,
                e.des_estado,
                cv.distrito,
                m.des_municipio,
                cv.municipio,
                p.des_parroquia,
                cv.nombre,
                cv.direccion
            FROM AC a
            JOIN conversion_centro_votacion ccv ON a.centro_votacion = ccv.codigo_actual
            JOIN centro_votacion cv ON a.centro_votacion = cv.codigo
            LEFT JOIN estado e ON cv.estado = e.cod_estado
            LEFT JOIN municipio m ON cv.estado = m.cod_estado AND cv.distrito = m.cod_municipio
            LEFT JOIN parroquia p ON cv.estado = p.cod_estado AND cv.distrito = p.cod_municipio AND cv.municipio = p.cod_parroquia
            WHERE a.NACIONALIDAD = :nacionalidad AND a.CEDULA = :cedula
        "#;

        let mut rows_actual = conn.query(sql_centro_actual, &[&nac_clone, &cedula]).map_err(|e| {
            log::error!("❌ Error query centro actual consolidado: {}", e);
            e.to_string()
        })?;

        if let Some(r_actual) = rows_actual.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo centro actual consolidado: {}", e);
            e.to_string()
        })? {
            let codigo_centro_actual_nuevo: Option<String> = r_actual.get(0).ok();
            let cod_estado_val: Option<i64> = r_actual.get(1).ok();
            let des_estado_actual: Option<String> = r_actual.get(2).ok();
            let cod_mun_val: Option<i64> = r_actual.get(3).ok();
            let des_municipio_actual: Option<String> = r_actual.get(4).ok();
            let cod_parr_val: Option<i64> = r_actual.get(5).ok();
            let des_parroquia_actual: Option<String> = r_actual.get(6).ok();
            let nombre_centro_actual: Option<String> = r_actual.get(7).ok();
            let direccion_centro_actual: Option<String> = r_actual.get(8).ok();

            resp.codigo_centro_actual = codigo_centro_actual_nuevo
                .as_deref()
                .and_then(normalize_codigo_centro_9);

            resp.estado_actual = Some(match cod_estado_val {
                Some(v) => fmt_geo(v, des_estado_actual),
                None => fmt_geo_sigla("EDO.", des_estado_actual),
            });
            resp.municipio_actual = Some(match cod_mun_val {
                Some(v) => fmt_geo(v, des_municipio_actual),
                None => fmt_geo_sigla("MP.", des_municipio_actual),
            });
            resp.parroquia_actual = Some(match cod_parr_val {
                Some(v) => fmt_geo(v, des_parroquia_actual),
                None => fmt_geo_sigla("PQ.", des_parroquia_actual),
            });
            resp.nombre_centro_actual = nombre_centro_actual;
            resp.direccion_centro_actual = direccion_centro_actual;
        }

        set_no_aplica_miembro(&mut resp);

        Ok(Some(resp))
    })
    .await
    .map_err(|e| {
        log::error!("❌ Error en blocking task elector: {}", e);
        actix_web::error::ErrorInternalServerError("Error interno del servidor")
    })?
    .map_err(|_| actix_web::error::ErrorInternalServerError("Error interno del servidor"))?;

    let mut resp = match resp_opt {
        Some(r) => r,
        None => return Ok(HttpResponse::NotFound().body("Elector no encontrado")),
    };

    let sql_miembro = r#"
    SELECT
        mm.nac,
        mm.cedula,
        mm.cod_centro,
        mm.cod_cargo,
        COALESCE(c.cargo, 'No aplica') AS cargo,
        mm.tipo_sorteo,
        COALESCE(o.organismo, 'No aplica') AS organismo,
        mm.cod_mesa,
        mm.mesa_electoral,
        CASE
            WHEN mm.centro_nuevo IS NULL
              OR TRIM(mm.centro_nuevo) = ''
              OR TRIM(mm.centro_nuevo) = '0'
            THEN NULL
            ELSE LPAD(REGEXP_REPLACE(mm.centro_nuevo, '\D', '', 'g'), 9, '0')
        END AS centro_nuevo
    FROM miembros_mesa mm
    LEFT JOIN miembros_mesa_cargos c
        ON c.cod_org = mm.tipo_sorteo
       AND c.cod_cargo = mm.cod_cargo
    LEFT JOIN miembros_mesa_organismos o
        ON o.cod_org = mm.tipo_sorteo
    WHERE mm.nac = $1
      AND mm.cedula = $2
    LIMIT 1
"#;

match sqlx::query(sql_miembro)
    .bind(&nacionalidad)
    .bind(cedula_int)
    .fetch_optional(&app_state.pool_pg)
    .await
{
    Ok(Some(miembro_row)) => {
        let cargo: String = miembro_row
            .try_get("cargo")
            .unwrap_or_else(|_| "No aplica".to_string());

        let organismo: String = miembro_row
            .try_get("organismo")
            .unwrap_or_else(|_| "No aplica".to_string());

        let tipo_sorteo: Option<i32> = miembro_row
            .try_get("tipo_sorteo")
            .ok()
            .flatten();

        let cod_mesa: Option<i32> = miembro_row
            .try_get("cod_mesa")
            .ok()
            .flatten();

        let mesa_electoral: Option<i32> = miembro_row
            .try_get("mesa_electoral")
            .ok()
            .flatten();

        let centro_nuevo: Option<String> = miembro_row
            .try_get("centro_nuevo")
            .ok()
            .flatten();

        resp.miembro_mesa_es_miembro = Some(true);
        resp.miembro_mesa_organismo = Some(organismo);
        resp.miembro_mesa_cargo = Some(cargo);
        resp.miembro_mesa_numero_mesa = mesa_electoral.map(|v| v as i64);
        resp.miembro_mesa_codigo_mesa = cod_mesa.map(|v| v as i64);
        resp.miembro_mesa_mesa_electoral = mesa_electoral.map(|v| v as i64);
        resp.miembro_mesa_tipo_sorteo = tipo_sorteo.map(|v| v as i64);
        resp.miembro_mesa_codigo_centro = Some(
            centro_nuevo
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "No aplica".to_string()),
        );
    }
    Ok(None) => {
        set_no_aplica_miembro(&mut resp);
    }
    Err(e) => {
        log::error!("❌ Error consultando miembro_mesa en PostgreSQL: {}", e);
        return Err(actix_web::error::ErrorInternalServerError(
            "Error interno del servidor",
        ));
    }
}

    if operador {
        aplicar_filtro_operador(&mut resp);
    }

    if let Some(autor_id) = get_autor_id(&req) {
        let ip_origen = crate::modules::logging::extract_ip(&req);
        let user_agent = crate::modules::logging::extract_user_agent(&req);
        let log_entry = log_consultar_datos_elector_entry(autor_id, cedula_int, ip_origen, user_agent);
        let pool_clone = app_state.pool_pg.clone();
        tokio::spawn(async move {
            let _ = crate::modules::logging::registrar_log(&pool_clone, log_entry).await;
        });
    }

    Ok(HttpResponse::Ok().json(resp))
}

// =====================
// Lista de electores
// =====================

#[derive(Deserialize)]
pub struct ElectoresQuery {
    pub nacionalidad: Option<String>,
    pub cedula: Option<i64>,
    pub fecha_nacimiento: Option<String>,
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub codigo_centro: Option<String>,
    pub global: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(serde::Serialize, Default)]
pub struct ElectorListaItem {
    pub nacionalidad: String,
    pub cedula: i64,
    pub fecha_nacimiento: Option<String>,
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub codigo_centro: Option<String>,
}

#[derive(serde::Serialize, Default)]
pub struct ElectoresPagedResponse {
    pub items: Vec<ElectorListaItem>,
    pub page: u32,
    pub limit: u32,
    has_more: bool,
}

fn normalize_date(input: Option<&str>) -> Option<String> {
    let s = input?.trim();
    if s.is_empty() {
        return None;
    }

    let binding = s
        .replace("--", "-")
        .replace("- -", "-")
        .replace("  ", " ")
        .replace("/", "-");
    let clean = binding.trim();

    if clean.contains('-') {
        let parts: Vec<&str> = clean.split('-').filter(|p| !p.is_empty()).collect();
        if parts.len() >= 3 {
            let y = parts[0];
            let m = parts[1];
            let d = parts[2];

            if y.len() == 4 && y.chars().all(|c| c.is_ascii_digit()) {
                let mm: u32 = m.parse().ok()?;
                let dd: u32 = d.parse().ok()?;
                if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
                    return Some(format!("{}-{:02}-{:02}", y, mm, dd));
                }
            }
        }
    }

    if clean.len() == 8 && clean.chars().all(|c| c.is_ascii_digit()) {
        let y = &clean[0..4];
        let m = &clean[4..6];
        let d = &clean[6..8];
        let mm: u32 = m.parse().ok()?;
        let dd: u32 = d.parse().ok()?;
        if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
            return Some(format!("{}-{}-{}", y, m, d));
        }
    }

    let digits: String = clean.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 8 {
        let y = &digits[0..4];
        let m = &digits[4..6];
        let d = &digits[6..8];
        let mm: u32 = m.parse().ok()?;
        let dd: u32 = d.parse().ok()?;
        if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
            return Some(format!("{}-{:02}-{:02}", y, mm, dd));
        }
    }

    None
}

pub async fn get_electores(
    req: HttpRequest,
    query: web::Query<ElectoresQuery>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(res) = require_consulta_basica(&req) {
        return Ok(res);
    }

    let q = query.into_inner();

    let hay_dato = q.cedula.is_some()
        || q.fecha_nacimiento.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.primer_nombre.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.segundo_nombre.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.primer_apellido.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.segundo_apellido.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.codigo_centro.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.nacionalidad.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || q.global.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);

    if !hay_dato {
        return Err(actix_web::error::ErrorBadRequest("Ingrese al menos un dato para buscar"));
    }

    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(9).clamp(1, 100);
    let fetch_limit = limit + 1;
    let offset = ((page - 1) * limit) as i64;
    let end_row = offset + fetch_limit as i64;

    let mut binds_str: Vec<(String, String)> = vec![];
    let mut binds_i64: Vec<(String, i64)> = vec![];

    fn eq_param(s: &str) -> String {
        s.trim().to_uppercase()
    }

    let has_centro = q.codigo_centro.as_ref().map(|x| !x.trim().is_empty()).unwrap_or(false);
    let global_is_num = q.global.as_ref().map(|x| x.trim().parse::<i64>().is_ok()).unwrap_or(false);
    let needs_centro_in_filter = has_centro || global_is_num;

    let mut where_clause = String::from("WHERE 1=1");

    if let Some(nac) = q.nacionalidad.as_ref().map(|x| x.trim().to_uppercase()) {
        if nac == "V" || nac == "E" {
            where_clause.push_str(" AND a.NACIONALIDAD = :nacionalidad ");
            binds_str.push(("nacionalidad".into(), nac));
        }
    }

    if let Some(ced) = q.cedula {
        if ced <= 0 || ced > 99_999_999 {
            return Err(actix_web::error::ErrorBadRequest("cédula inválida"));
        }
        where_clause.push_str(" AND a.CEDULA = :cedula ");
        binds_i64.push(("cedula".into(), ced));
    }

    if let Some(fnac_input) = q.fecha_nacimiento.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let iso = normalize_date(Some(fnac_input))
            .ok_or_else(|| actix_web::error::ErrorBadRequest("fecha_nacimiento inválida (use YYYY-MM-DD o YYYYMMDD)"))?;

        where_clause.push_str(" AND a.FECHA_NACIMIENTO_4 LIKE :fecha_nacimiento || '%' ");
        binds_str.push(("fecha_nacimiento".into(), iso.replace("-", "")));
    }

    if let Some(s) = q.primer_nombre.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        where_clause.push_str(" AND a.PRIMER_NOMBRE LIKE :primer_nombre || '%' ");
        binds_str.push(("primer_nombre".into(), eq_param(s)));
    }

    if let Some(s) = q.segundo_nombre.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        where_clause.push_str(" AND a.SEGUNDO_NOMBRE LIKE :segundo_nombre || '%' ");
        binds_str.push(("segundo_nombre".into(), eq_param(s)));
    }

    if let Some(s) = q.primer_apellido.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        where_clause.push_str(" AND a.PRIMER_APELLIDO LIKE :primer_apellido || '%' ");
        binds_str.push(("primer_apellido".into(), eq_param(s)));
    }

    if let Some(s) = q.segundo_apellido.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        where_clause.push_str(" AND a.SEGUNDO_APELLIDO LIKE :segundo_apellido || '%' ");
        binds_str.push(("segundo_apellido".into(), eq_param(s)));
    }

    if let Some(s) = q.codigo_centro.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        match s.parse::<i64>() {
            Ok(codigo) => {
                where_clause.push_str(" AND v.CODIGO_NUEVO = :codigo_centro ");
                binds_i64.push(("codigo_centro".into(), codigo));
            }
            Err(_) => {
                return Err(actix_web::error::ErrorBadRequest(
                    "codigo_centro inválido (debe ser numérico)",
                ));
            }
        }
    }

    if let Some(s) = q.global.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        if let Ok(num) = s.parse::<i64>() {
            where_clause.push_str(" AND (a.CEDULA = :global_ced OR v.CODIGO_NUEVO = :global_centro) ");
            binds_i64.push(("global_ced".into(), num));
            binds_i64.push(("global_centro".into(), num));
        } else {
            let term = eq_param(s);
            where_clause.push_str(" AND (a.PRIMER_NOMBRE LIKE :global_nombre || '%' OR a.PRIMER_APELLIDO LIKE :global_apellido || '%') ");
            binds_str.push(("global_nombre".into(), term.clone()));
            binds_str.push(("global_apellido".into(), term));
        }
    }

    // ✅ Optimización de consulta con ordenamiento global por Cédula:
    // Aplicamos Deferred Join (filtrando, ordenando por a.CEDULA y paginando primero sobre RE.AC,
    // y uniendo CONVERSION_CENTRO_VOTACION únicamente para los registros de la página final).
    // Esto permite a Oracle usar los índices de RE.AC con STOPKEY en ~8-75ms ordenando desde la primera hasta la última cédula.
    let sql_select = if needs_centro_in_filter {
        format!(
            r#"
            SELECT
                p.NACIONALIDAD,
                p.CEDULA,
                p.PRIMER_NOMBRE,
                p.SEGUNDO_NOMBRE,
                p.PRIMER_APELLIDO,
                p.SEGUNDO_APELLIDO,
                p.FECHA_NACIMIENTO,
                p.CODIGO_CENTRO_VOTACION
            FROM (
                SELECT t_inner.*, ROWNUM rn
                FROM (
                    SELECT
                        a.NACIONALIDAD,
                        a.CEDULA,
                        a.PRIMER_NOMBRE,
                        a.SEGUNDO_NOMBRE,
                        a.PRIMER_APELLIDO,
                        a.SEGUNDO_APELLIDO,
                        a.FECHA_NACIMIENTO_4 AS FECHA_NACIMIENTO,
                        TO_CHAR(v.CODIGO_NUEVO) AS CODIGO_CENTRO_VOTACION
                    FROM RE.CONVERSION_CENTRO_VOTACION v JOIN RE.AC a ON a.CENTRO_VOTACION = v.CODIGO_ACTUAL
                    {}
                    ORDER BY a.CEDULA ASC
                ) t_inner
                WHERE ROWNUM <= :end_row
            ) p
            WHERE p.rn > :offset
            ORDER BY p.CEDULA ASC
            "#,
            where_clause
        )
    } else {
        format!(
            r#"
            SELECT
                p.NACIONALIDAD,
                p.CEDULA,
                p.PRIMER_NOMBRE,
                p.SEGUNDO_NOMBRE,
                p.PRIMER_APELLIDO,
                p.SEGUNDO_APELLIDO,
                p.FECHA_NACIMIENTO,
                TO_CHAR(v.CODIGO_NUEVO) AS CODIGO_CENTRO_VOTACION
            FROM (
                SELECT t_inner.*, ROWNUM rn
                FROM (
                    SELECT
                        a.NACIONALIDAD,
                        a.CEDULA,
                        a.PRIMER_NOMBRE,
                        a.SEGUNDO_NOMBRE,
                        a.PRIMER_APELLIDO,
                        a.SEGUNDO_APELLIDO,
                        a.FECHA_NACIMIENTO_4 AS FECHA_NACIMIENTO,
                        a.CENTRO_VOTACION
                    FROM RE.AC a
                    {}
                    ORDER BY a.CEDULA ASC
                ) t_inner
                WHERE ROWNUM <= :end_row
            ) p
            LEFT JOIN RE.CONVERSION_CENTRO_VOTACION v ON p.CENTRO_VOTACION = v.CODIGO_ACTUAL
            WHERE p.rn > :offset
            ORDER BY p.CEDULA ASC
            "#,
            where_clause
        )
    };

    let pool_oracle = app_state.pool_oracle.clone();
    let (items, has_more) = web::block(move || -> Result<(Vec<ElectorListaItem>, bool), String> {
        let conn = pool_oracle.get().map_err(|e| {
            log::error!("❌ Error obteniendo conexión de Oracle Pool: {}", e);
            e.to_string()
        })?;

        let offset_holder = offset;
        let end_row_holder = end_row;

        let mut select_params: Vec<(&str, &dyn oracle::sql_type::ToSql)> = Vec::new();

        for (k, v) in &binds_str {
            select_params.push((k.as_str(), v as &dyn oracle::sql_type::ToSql));
        }
        for (k, v) in &binds_i64 {
            select_params.push((k.as_str(), v as &dyn oracle::sql_type::ToSql));
        }
        select_params.push(("end_row", &end_row_holder as &dyn oracle::sql_type::ToSql));
        select_params.push(("offset", &offset_holder as &dyn oracle::sql_type::ToSql));

        let t_select = Instant::now();
        let mut rows_data = conn.query_named(&sql_select, &select_params).map_err(|e| {
            log::error!("❌ Error en SELECT de electores: {}", e);
            e.to_string()
        })?;
        log::info!("⏱️ get_electores SELECT ms = {}", t_select.elapsed().as_millis());

        let t_fetch = Instant::now();
        let mut items: Vec<ElectorListaItem> = Vec::new();

        while let Some(row) = rows_data.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo filas: {}", e);
            e.to_string()
        })? {
            let nac: String = row.get(0).unwrap_or_else(|_| "V".to_string());
            let ced: i64 = row.get(1).unwrap_or(0);
            let primer_nombre: Option<String> = row.get(2).ok();
            let segundo_nombre: Option<String> = row.get(3).ok();
            let primer_apellido: Option<String> = row.get(4).ok();
            let segundo_apellido: Option<String> = row.get(5).ok();
            let fecha_raw: Option<String> = row.get(6).ok();

            let fecha_iso = if let Some(f) = fecha_raw {
                if f.len() >= 8 {
                    Some(format!("{}-{}-{}", &f[0..4], &f[4..6], &f[6..8]))
                } else {
                    Some(f)
                }
            } else {
                None
            };

            let codigo_centro: Option<String> = row.get(7).ok();

            items.push(ElectorListaItem {
                nacionalidad: nac,
                cedula: ced,
                fecha_nacimiento: fecha_iso,
                primer_nombre,
                segundo_nombre,
                primer_apellido,
                segundo_apellido,
                codigo_centro,
            });
        }

        let has_more = items.len() as u32 > limit;
        if has_more {
            items.truncate(limit as usize);
        }

        // ✅ Ordenamiento en memoria RAM por cédula ascendente sin penalizar Oracle con ORDER BY
        items.sort_by(|a, b| {
            a.cedula
                .cmp(&b.cedula)
                .then_with(|| a.nacionalidad.cmp(&b.nacionalidad))
        });

        log::info!(
            "⏱️ get_electores FETCH rows={} ms = {}",
            items.len(),
            t_fetch.elapsed().as_millis()
        );

        Ok((items, has_more))
    })
    .await
    .map_err(|e| {
        log::error!("❌ Error en blocking task get_electores: {}", e);
        actix_web::error::ErrorInternalServerError("Error interno del servidor")
    })?
    .map_err(|_| actix_web::error::ErrorInternalServerError("Error interno del servidor"))?;

    Ok(HttpResponse::Ok().json(ElectoresPagedResponse {
        items,
        page,
        limit,
        has_more,
    }))
}

// =====================
// Votos a emitir
// =====================

#[derive(serde::Serialize, Default)]
pub struct VotosEmitirResponse {
    pub circ_consejo_nom: i32,
    pub circ_asamblea_leg: i32,
    pub alcalde_distrital: i32,
    pub alcalde_metropolitano: i32,
    pub alcalde_municipal: i32,
    pub concejal_cabildo_dist_lista: i32,
    pub concejal_cabildo_dist_nom: i32,
    pub concejal_municipal_lista: i32,
    pub concejal_municipal_nom: i32,
    pub diputado_nom_asamb_nac: i32,
    pub diputado_ind_asamb_nac: i32,
    pub diputado_lista_asamb_nac: i32,
    pub diputados_consejo_leg_list: i32,
    pub diputados_consejo_leg_nom: i32,
    pub diputados_parlamento_andino: i32,
    pub diputados_parlam_lat_ame: i32,
    pub gobernador: i32,
    pub presidente: i32,
    pub referendos: i32,
    pub concejal_cabildo_metrop_nom: i32,
    pub concejal_cabildo_metrop_list: i32,
    pub repres_ind_cabildo_dist: i32,
    pub repres_ind_concejal_mun: i32,
    pub representante_consejo_leg: i32,
    pub junta_parroquial_nominal: i32,
    pub junta_parroquial_lista: i32,
}

fn parse_i32_opt(s: Option<String>) -> i32 {
    let t = s.unwrap_or_default().trim().to_string();
    if t.is_empty() || t.eq_ignore_ascii_case("no aplica") {
        return 0;
    }
    t.parse::<i32>().unwrap_or(0)
}

pub async fn get_votos_emitir(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log};

    if let Err(res) = require_consulta_completa(&req) {
        return Ok(res);
    }

    let (nacionalidad_raw, cedula_raw) = path.into_inner();
    let nacionalidad = nacionalidad_raw.trim().to_uppercase();
    let cedula: i64 = cedula_raw
        .trim()
        .parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("cedula inválida"))?;
    let cedula_int: i32 = cedula as i32;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let pool_oracle = app_state.pool_oracle.clone();
    let nac_clone = nacionalidad.clone();

    let resp = web::block(move || -> Result<VotosEmitirResponse, String> {
        let conn = pool_oracle.get().map_err(|e| {
            log::error!("❌ Error obteniendo conexión de Oracle Pool: {}", e);
            e.to_string()
        })?;

        let sql_votos = r#"
            SELECT 
                ve.CIRC_CONCEJ, ve.CIRC_ASAMB_LEG, ve.PRESIDENTE, ve.DIP_NOM_ASAMB_NAC, ve.DIP_LIS_ASAMB_NAC,
                ve.DIP_IND_SAMB_NAC, ve.DIP_PARLAM_ANDINO, ve.DIP_PARLAM_LAT_AMER, ve.GOBERNADOR,
                ve.DIP_CONC_LEG_NOM, ve.DIP_CONC_LEG_LIS, ve.REP_IND_CONC_LEG, ve.ALCALD_METROPOL,
                ve.CONC_CAB_METROP_NOM, ve.CONC_CAB_METROP_LIS, ve.ALCALDE_DISTRITAL, ve.CONC_CAB_DIST_NOM,
                ve.CONC_CAB_DIST_LIS, ve.REP_IND_CAB_DIST, ve.ALCALDE_MUNICIPAL, ve.CONC_MUNIC_NOM,
                ve.CONC_MUNIC_LIS, ve.REP_IND_CONC_MUNIC, ve.JUNTA_PARRQ_NOM, ve.JUNTA_PARRQ_LIS, ve.REFERENDOS
            FROM RE.AC a
            JOIN RE.CENTRO_VOTACION cv ON a.CENTRO_VOTACION = cv.CODIGO
            JOIN MC.VOTOS_EMITIR ve 
              ON TO_NUMBER(cv.ESTADO) = ve.COD_ESTADO 
             AND TO_NUMBER(cv.DISTRITO) = ve.COD_MUNICIPIO 
             AND TO_NUMBER(cv.MUNICIPIO) = ve.COD_PARROQ
            WHERE a.NACIONALIDAD = :nac AND a.CEDULA = :ced
        "#;

        let mut rows_v = conn
            .query(sql_votos, &[&nac_clone, &cedula])
            .map_err(|e| {
                log::error!("❌ Error votos query consolidado: {}", e);
                e.to_string()
            })?;

        let row_v_opt = rows_v.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo votos: {}", e);
            e.to_string()
        })?;

        let r = match row_v_opt {
            Some(x) => x,
            None => {
                return Ok(VotosEmitirResponse::default());
            }
        };

        let get_s = |idx: usize| -> i32 {
            parse_i32_opt(r.get::<usize, Option<String>>(idx).ok().flatten())
        };

        Ok(VotosEmitirResponse {
            circ_consejo_nom: get_s(0),
            circ_asamblea_leg: get_s(1),
            presidente: get_s(2),
            diputado_nom_asamb_nac: get_s(3),
            diputado_lista_asamb_nac: get_s(4),
            diputado_ind_asamb_nac: get_s(5),
            diputados_parlamento_andino: get_s(6),
            diputados_parlam_lat_ame: get_s(7),
            gobernador: get_s(8),
            diputados_consejo_leg_nom: get_s(9),
            diputados_consejo_leg_list: get_s(10),
            representante_consejo_leg: get_s(11),
            alcalde_metropolitano: get_s(12),
            concejal_cabildo_metrop_nom: get_s(13),
            concejal_cabildo_metrop_list: get_s(14),
            alcalde_distrital: get_s(15),
            concejal_cabildo_dist_nom: get_s(16),
            concejal_cabildo_dist_lista: get_s(17),
            repres_ind_cabildo_dist: get_s(18),
            alcalde_municipal: get_s(19),
            concejal_municipal_nom: get_s(20),
            concejal_municipal_lista: get_s(21),
            repres_ind_concejal_mun: get_s(22),
            junta_parroquial_nominal: get_s(23),
            junta_parroquial_lista: get_s(24),
            referendos: get_s(25),
        })
    })
    .await
    .map_err(|e| {
        log::error!("❌ Error en blocking task votos: {}", e);
        actix_web::error::ErrorInternalServerError("Error interno del servidor")
    })?
    .map_err(|_| actix_web::error::ErrorInternalServerError("Error interno del servidor"))?;

    if let Some(autor_id) = get_autor_id(&req) {
        let ip_origen = extract_ip(&req);
        let user_agent = extract_user_agent(&req);
        let log_entry = log_votos_emitir_entry(autor_id, cedula_int, ip_origen, user_agent);
        let pool_clone = app_state.pool_pg.clone();
        tokio::spawn(async move {
            let _ = registrar_log(&pool_clone, log_entry).await;
        });
    }

    Ok(HttpResponse::Ok().json(resp))
}