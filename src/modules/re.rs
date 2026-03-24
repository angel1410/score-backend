use actix_web::{web, HttpResponse, Error, HttpRequest};
use oracle::{Connection, Row, RowValue};
use serde::Deserialize;
use std::env;
use std::time::Instant;
use crate::structs::AppState;
use crate::modules::logging::LogEntry;

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

// =====================
// Helper para obtener id_usuario del token
// =====================

async fn obtener_id_usuario_del_token(
    req: &HttpRequest,
    app_state: &web::Data<AppState>,
) -> Result<i32, String> {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Claims {
        sub: String,
        exp: usize,
        iat: usize,
    }

    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        log::warn!("⚠️ Token NO presente en request");
        return Err("Token no encontrado".to_string());
    }

    log::info!("🔑 Token presente para usuario");

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(app_state.jwt_secret.as_bytes()),
        &Validation::default()
    ) {
        Ok(token_data) => {
            let user_id = token_data.claims.sub.parse::<i32>()
                .map_err(|_| "ID inválido en token")?;
            log::info!("✅ Token decodificado exitosamente - User ID: {}", user_id);
            Ok(user_id)
        }
        Err(e) => {
            log::error!("❌ Error decodificando token: {}", e);
            Err("Token inválido".to_string())
        }
    }
}

// =====================
// Movimiento RE
// =====================

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

fn oracle_conn() -> Result<Connection, oracle::Error> {
    let username = env::var("ORACLE_USER").unwrap();
    let password = env::var("ORACLE_PASS").unwrap();
    let oracle_ip = env::var("ORACLE_IP").unwrap();
    let oracle_port = env::var("ORACLE_PORT").unwrap();
    let oracle_db = env::var("ORACLE_DB").unwrap();
    let connect_string = format!("//{oracle_ip}:{oracle_port}/{oracle_db}");
    Connection::connect(username, password, connect_string)
}

// ✅ MOVIMIENTOS RE CON LOGGING
pub async fn get_movimientos_re(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    use crate::modules::logging::registrar_log;

    let (nacionalidad, cedula_str) = path.into_inner();
    let nacionalidad = nacionalidad.to_uppercase();
    let cedula_int: i32 = cedula_str.parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("Cédula inválida"))?;

    log::info!("🔍 Movimientos RE - Cédula: {} {}", nacionalidad, cedula_int);

    let conn = oracle_conn()
        .map_err(|e| {
            log::error!("❌ Error conectando a Oracle: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e))
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

    let rows = conn.query_as::<MovimientoRE>(sql, &[&nacionalidad, &cedula_str])
        .map_err(|e| {
            log::error!("❌ Error ejecutando query: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Error ejecutando query: {}", e))
        })?;

    let mut re_array: Vec<MovimientoRE> = Vec::new();
    for row_result in rows {
        let mov = row_result
            .map_err(|e| {
                log::error!("❌ Error procesando fila: {}", e);
                actix_web::error::ErrorInternalServerError(format!("Error procesando fila: {}", e))
            })?;
        re_array.push(mov);
    }

    log::info!("✅ Movimientos RE encontrados: {}", re_array.len());

    if let Ok(autor_id) = obtener_id_usuario_del_token(&req, &app_state).await {
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
// Elector (para tu Dialog) CON LOGGING
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
    // ÚLTIMO EVENTO
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
    // CENTRO ACTUAL
    pub estado_actual: Option<String>,
    pub municipio_actual: Option<String>,
    pub parroquia_actual: Option<String>,
    pub codigo_centro_actual: Option<String>,
    pub nombre_centro_actual: Option<String>,
    pub direccion_centro_actual: Option<String>,
    // MIEMBRO DE MESA
    pub miembro_mesa_numero_mesa: Option<i64>,
    pub miembro_mesa_cargo: Option<String>,
    pub miembro_mesa_centro_capacitacion: Option<String>,
    pub miembro_mesa_nombre_centro_capacitacion: Option<String>,
    pub miembro_mesa_fecha_inicio_capacitacion: Option<String>,
    pub miembro_mesa_fecha_culminacion_capacitacion: Option<String>,
    pub miembro_mesa_horario_capacitacion: Option<String>,
    pub miembro_mesa_direccion_centro_capacitacion: Option<String>,
}

fn yyyymmdd_to_iso(s: &str) -> Option<String> {
    if s.len() < 8 { return None; }
    Some(format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]))
}

fn pad9(n: i64) -> String {
    format!("{:09}", n)
}

fn normalize_codigo_centro_9<S: AsRef<str>>(s: S) -> Option<String> {
    let trimmed = s.as_ref().trim();
    if trimmed.is_empty() { return None; }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() { return None; }
    let value = digits.parse::<i64>().ok()?;
    Some(format!("{:09}", value))
}

fn clean_geo_desc(s: String) -> String {
    let mut t = s.trim().to_string();
    let upper = t.to_uppercase();
    let prefixes = [
        "EDO.", "EDO", "ESTADO",
        "MP.", "MP", "MUN.", "MUN", "MUNICIPIO",
        "PQ.", "PQ", "PAR.", "PAR", "PARROQUIA",
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
    if s.len() < 8 { return None; }
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
    resp.miembro_mesa_numero_mesa = Some(0);
    resp.miembro_mesa_cargo = Some("No aplica".to_string());
    resp.miembro_mesa_centro_capacitacion = Some("0".to_string());
    resp.miembro_mesa_nombre_centro_capacitacion = Some("No aplica".to_string());
    resp.miembro_mesa_fecha_inicio_capacitacion = Some("No aplica".to_string());
    resp.miembro_mesa_fecha_culminacion_capacitacion = Some("No aplica".to_string());
    resp.miembro_mesa_horario_capacitacion = Some("No aplica".to_string());
    resp.miembro_mesa_direccion_centro_capacitacion = Some("No aplica".to_string());
}

// ✅ GET ELECTOR CON LOGGING
pub async fn get_elector(
    query: web::Query<ElectorQuery>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    use crate::modules::logging::registrar_log;

    let nac = query.nacionalidad.trim().to_uppercase();
    let nacionalidad = nac.chars().next().unwrap_or('V').to_string();
    let cedula = query.cedula;
    let cedula_int = cedula as i32;

    log::info!("🔍 Consultar Datos Elector - Cédula: {} {}", nacionalidad, cedula);

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let conn = oracle_conn().map_err(|e| {
        log::error!("❌ Error conectando a Oracle: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e))
    })?;

    let mut resp = ElectorResponse {
        nacionalidad: nacionalidad.clone(),
        cedula,
        ..Default::default()
    };

    // =====================
    // DATOS PERSONALES
    // =====================
    let sql_persona = r#"
        SELECT AC.PRIMER_APELLIDO, AC.SEGUNDO_APELLIDO, AC.PRIMER_NOMBRE, AC.SEGUNDO_NOMBRE,
        AC.FECHA_NACIMIENTO_4, AC.STATUS_OBJECION, OBJ.DESCRIPCION,
        MD.CIUDAD, MD.URBANIZACION, MD.SECTOR, MD.AVENIDA_CALLE, MD.EDIFICIO_CASA, MD.APARTAMENTO
        FROM AC AC
        JOIN OBJECION OBJ ON AC.STATUS_OBJECION = OBJ.STATUS
        LEFT JOIN RE.MAESTRO_DIRECCION MD ON MD.NACIONALIDAD = AC.NACIONALIDAD AND MD.CEDULA = AC.CEDULA
        WHERE AC.NACIONALIDAD = :nacionalidad AND AC.CEDULA = :cedula
    "#;

    let mut rows = conn.query(sql_persona, &[&nacionalidad, &cedula]).map_err(|e| {
        log::error!("❌ Error query persona: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error query persona: {}", e))
    })?;

    let row_opt = rows.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo persona: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo persona: {}", e))
    })?;

    let row = match row_opt {
        Some(r) => r,
        None => {
            log::warn!("⚠️ Elector no encontrado: {} {}", nacionalidad, cedula);
            return Ok(HttpResponse::NotFound().body("Elector no encontrado"));
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

    // =====================
    // IDENTIFICACIÓN ELECTORAL - ÚLTIMO EVENTO
    // =====================
    let sql_cuaderno = r#"
        SELECT nu_mesa, nu_pagina, nu_renglon, nu_edad_al_evento, fe_evento,
        cod_estado, cod_municipio, cod_parroquia, nu_centro
        FROM instrumentos.cuaderno_actual2
        WHERE co_nacionalidad = :nacionalidad AND nu_cedula = :cedula
    "#;

    let mut rows2 = conn.query(sql_cuaderno, &[&nacionalidad, &cedula]).map_err(|e| {
        log::error!("❌ Error query cuaderno: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error query cuaderno: {}", e))
    })?;

    let row2_opt = rows2.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo cuaderno: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo cuaderno: {}", e))
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
            actix_web::error::ErrorInternalServerError(format!("Error query vista geografica: {}", e))
        })?;

        if let Some(r3) = rows3.next().transpose().map_err(|e| {
            log::error!("❌ Error leyendo vista geografica: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Error leyendo vista geografica: {}", e))
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

    // =====================
    // IDENTIFICACIÓN ELECTORAL - ACTUAL
    // =====================
    let sql_centro_actual_base = r#"
        SELECT a.fecha_nacimiento_4, a.centro_votacion, ccv.codigo_nuevo, cv.estado, cv.distrito, cv.municipio
        FROM AC a, CENTRO_VOTACION cv, conversion_centro_votacion ccv
        WHERE a.NACIONALIDAD = :nacionalidad
        AND a.CEDULA = :cedula
        AND a.centro_votacion = cv.codigo
        AND a.centro_votacion = ccv.codigo_actual
    "#;

    let mut rows_actual_base = conn.query(sql_centro_actual_base, &[&nacionalidad, &cedula]).map_err(|e| {
        log::error!("❌ Error query centro actual base: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error query centro actual base: {}", e))
    })?;

    if let Some(r_actual_base) = rows_actual_base.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo centro actual base: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo centro actual base: {}", e))
    })? {
        let codigo_centro_actual_viejo: Option<String> = r_actual_base.get(1).ok();
        let codigo_centro_actual_nuevo: Option<String> = r_actual_base.get(2).ok();
        let cod_estado_actual: Option<String> = r_actual_base.get(3).ok();
        let cod_municipio_actual: Option<String> = r_actual_base.get(4).ok();
        let cod_parroquia_actual: Option<String> = r_actual_base.get(5).ok();

        resp.codigo_centro_actual = codigo_centro_actual_nuevo
            .as_deref()
            .and_then(normalize_codigo_centro_9);

        if let (Some(codigo_centro_viejo), Some(ce_str), Some(cm_str), Some(cp_str)) = 
            (codigo_centro_actual_viejo, cod_estado_actual, cod_municipio_actual, cod_parroquia_actual) {
            
            let ce_num = ce_str.trim().parse::<i64>().ok();
            let cm_num = cm_str.trim().parse::<i64>().ok();
            let cp_num = cp_str.trim().parse::<i64>().ok();

            let sql_centro_actual_detalle = r#"
                SELECT estado.des_estado as nEstado, municipio.des_municipio as nMun,
                parroquia.des_parroquia as nParr, centro.nombre, centro.direccion
                FROM estado estado, municipio municipio, parroquia parroquia, centro_votacion centro
                WHERE parroquia.cod_municipio = municipio.cod_municipio
                AND parroquia.cod_estado = estado.cod_estado
                AND municipio.cod_estado = estado.cod_estado
                AND centro.codigo = :codigo_centro
                AND centro.estado = parroquia.cod_estado
                AND centro.distrito = parroquia.cod_municipio
                AND centro.municipio = parroquia.cod_parroquia
                AND parroquia.cod_municipio = :cod_municipio
                AND parroquia.cod_estado = :cod_estado
                AND parroquia.cod_parroquia = :cod_parroquia
            "#;

            let mut rows_actual_detalle = match (ce_num, cm_num, cp_num) {
                (Some(ce), Some(cm), Some(cp)) => conn
                    .query(sql_centro_actual_detalle, &[&codigo_centro_viejo, &cm, &ce, &cp])
                    .map_err(|e| {
                        log::error!("❌ Error query centro actual detalle: {}", e);
                        actix_web::error::ErrorInternalServerError(format!("Error query centro actual detalle: {}", e))
                    })?,
                _ => {
                    log::warn!("⚠️ No se pudieron convertir códigos geográficos actuales");
                    conn.query("SELECT 1 FROM dual WHERE 1=0", &[]).map_err(|e| {
                        log::error!("❌ Error query dummy detalle actual: {}", e);
                        actix_web::error::ErrorInternalServerError(format!("Error query dummy detalle actual: {}", e))
                    })?
                }
            };

            if let Some(r_actual_detalle) = rows_actual_detalle.next().transpose().map_err(|e| {
                log::error!("❌ Error leyendo centro actual detalle: {}", e);
                actix_web::error::ErrorInternalServerError(format!("Error leyendo centro actual detalle: {}", e))
            })? {
                let des_estado_actual: Option<String> = r_actual_detalle.get(0).ok();
                let des_municipio_actual: Option<String> = r_actual_detalle.get(1).ok();
                let des_parroquia_actual: Option<String> = r_actual_detalle.get(2).ok();
                let nombre_centro_actual: Option<String> = r_actual_detalle.get(3).ok();
                let direccion_centro_actual: Option<String> = r_actual_detalle.get(4).ok();

                resp.estado_actual = Some(match ce_num {
                    Some(v) => fmt_geo(v, des_estado_actual),
                    None => fmt_geo_sigla("EDO.", des_estado_actual),
                });
                resp.municipio_actual = Some(match cm_num {
                    Some(v) => fmt_geo(v, des_municipio_actual),
                    None => fmt_geo_sigla("MP.", des_municipio_actual),
                });
                resp.parroquia_actual = Some(match cp_num {
                    Some(v) => fmt_geo(v, des_parroquia_actual),
                    None => fmt_geo_sigla("PQ.", des_parroquia_actual),
                });
                resp.nombre_centro_actual = nombre_centro_actual;
                resp.direccion_centro_actual = direccion_centro_actual;
            }
        }
    }

    // =====================
    // MIEMBRO DE MESA
    // =====================
    set_no_aplica_miembro(&mut resp);

    let sql_miembro = r#"
        SELECT miembro.mesa, cargo_miembro.descripcion_cargo, miembro.centrocap, c_capacitacion.nombre,
        miembro.tallerdesde, miembro.tallerhasta, miembro.horario, c_capacitacion.direccion
        FROM miembros_oes miembro, cargos_miembros_oes cargo_miembro, tipos_oes t_oes, MC.centro_capacitacion c_capacitacion
        WHERE t_oes.tipo_oes = cargo_miembro.tipo_oes AND cargo_miembro.tipo_oes = miembro.timioes
        AND miembro.cargo = cargo_miembro.cod_cargo AND miembro.centrocap = c_capacitacion.codigo
        AND miembro.nac = :nacionalidad AND miembro.cedula = :cedula
    "#;

    let mut rowsm = conn.query(sql_miembro, &[&nacionalidad, &cedula]).map_err(|e| {
        log::error!("❌ Error query miembro_mesa: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error query miembro_mesa: {}", e))
    })?;

    if let Some(rm) = rowsm.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo miembro_mesa: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo miembro_mesa: {}", e))
    })? {
        let mesa: Option<i64> = rm.get(0).ok();
        resp.miembro_mesa_numero_mesa = Some(mesa.unwrap_or(0));
        resp.miembro_mesa_cargo = rm.get(1).ok();
        let centrocap: Option<String> = rm.get(2).ok();
        resp.miembro_mesa_centro_capacitacion = Some(centrocap.unwrap_or_else(|| "0".to_string()));
        resp.miembro_mesa_nombre_centro_capacitacion = rm.get(3).ok();

        let desde: Option<String> = rm.get(4).ok();
        resp.miembro_mesa_fecha_inicio_capacitacion = desde.as_deref().and_then(ddmmyyyy).or(Some("No aplica".to_string()));
        let hasta: Option<String> = rm.get(5).ok();
        resp.miembro_mesa_fecha_culminacion_capacitacion = hasta.as_deref().and_then(ddmmyyyy).or(Some("No aplica".to_string()));
        let horario: Option<String> = rm.get(6).ok();
        resp.miembro_mesa_horario_capacitacion = horario.as_deref().and_then(fmt_horario).or(Some("No aplica".to_string()));
        resp.miembro_mesa_direccion_centro_capacitacion = rm.get(7).ok();
    }

    log::info!("✅ Datos elector obtenidos exitosamente");

    if let Ok(autor_id) = obtener_id_usuario_del_token(&req, &app_state).await {
        let ip_origen = crate::modules::logging::extract_ip(&req);
        let user_agent = crate::modules::logging::extract_user_agent(&req);
        let log_entry = log_consultar_datos_elector_entry(autor_id, cedula_int, ip_origen, user_agent);
        let pool_clone = app_state.pool_pg.clone();
        tokio::spawn(async move {
            let _ = registrar_log(&pool_clone, log_entry).await;
        });
    }

    Ok(HttpResponse::Ok().json(resp))
}

// =====================
// Lista de electores - OPTIMIZADA (solo búsqueda por nombres y fecha)
// =====================
// =====================
// Lista de electores - OPTIMIZADA CON BÚSQUEDAS FLEXIBLES
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

// Normalizar fecha a formato YYYY-MM-DD
fn normalize_date(input: Option<&str>) -> Option<String> {
    let s = input?.trim();
    if s.is_empty() {
        return None;
    }
    
    // Limpiar formato
    let binding = s
        .replace("--", "-")
        .replace("- -", "-")
        .replace("  ", " ")
        .replace("/", "-");
    let clean = binding.trim();
    
    // Formato YYYY-MM-DD
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
    
    // Formato YYYYMMDD (8 dígitos)
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
    
    // Extraer solo dígitos
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

// ✅ GET ELECTORES - VERSIÓN OPTIMIZADA CON BÚSQUEDAS FLEXIBLES
pub async fn get_electores(query: web::Query<ElectoresQuery>) -> Result<HttpResponse, Error> {
    let q = query.into_inner();
    
    // Validar que al menos haya un criterio de búsqueda
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
    
    // Paginación
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(9).clamp(1, 100);
    let fetch_limit = limit + 1; // Para saber si hay más
    let offset = ((page - 1) * limit) as i64;
    let end_row = offset + fetch_limit as i64;
    
    let conn = oracle_conn().map_err(|e| {
        log::error!("❌ Error conectando a Oracle: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e))
    })?;
    
    // Construir WHERE dinámico
    let mut from_where = String::from(" FROM RE.AC_MD_VIEW WHERE 1=1 ");
    let mut binds_str: Vec<(String, String)> = vec![];
    let mut binds_i64: Vec<(String, i64)> = vec![];
    
    // Helper para normalizar a mayúsculas
    fn eq_param(s: &str) -> String {
        s.trim().to_uppercase()
    }
    
    // Nacionalidad
    if let Some(nac) = q.nacionalidad.as_ref().map(|x| x.trim().to_uppercase()) {
        if nac == "V" || nac == "E" {
            from_where.push_str(" AND NACIONALIDAD = :nacionalidad ");
            binds_str.push(("nacionalidad".into(), nac));
        }
    }
    
    // Cédula (búsqueda exacta)
    if let Some(ced) = q.cedula {
        if ced <= 0 || ced > 99_999_999 {
            return Err(actix_web::error::ErrorBadRequest("cédula inválida"));
        }
        from_where.push_str(" AND CEDULA = :cedula ");
        binds_i64.push(("cedula".into(), ced));
    }
    
    // Fecha de nacimiento (búsqueda flexible)
    if let Some(fnac_input) = q.fecha_nacimiento.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let iso = normalize_date(Some(fnac_input))
            .ok_or_else(|| actix_web::error::ErrorBadRequest("fecha_nacimiento inválida (use YYYY-MM-DD o YYYYMMDD)"))?;
        
        // Búsqueda por prefijo (permite buscar por año, año-mes, o fecha completa)
        from_where.push_str(" AND FECHA_NACIMIENTO LIKE :fecha_nacimiento || '%' ");
        binds_str.push(("fecha_nacimiento".into(), iso.replace("-", "")));
    }
    
    // Primer Nombre (búsqueda con LIKE para mayor flexibilidad)
    if let Some(s) = q.primer_nombre.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        from_where.push_str(" AND PRIMER_NOMBRE LIKE :primer_nombre || '%' ");
        binds_str.push(("primer_nombre".into(), eq_param(s)));
    }
    
    // Segundo Nombre
    if let Some(s) = q.segundo_nombre.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        from_where.push_str(" AND SEGUNDO_NOMBRE LIKE :segundo_nombre || '%' ");
        binds_str.push(("segundo_nombre".into(), eq_param(s)));
    }
    
    // Primer Apellido
    if let Some(s) = q.primer_apellido.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        from_where.push_str(" AND PRIMER_APELLIDO LIKE :primer_apellido || '%' ");
        binds_str.push(("primer_apellido".into(), eq_param(s)));
    }
    
    // Segundo Apellido
    if let Some(s) = q.segundo_apellido.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        from_where.push_str(" AND SEGUNDO_APELLIDO LIKE :segundo_apellido || '%' ");
        binds_str.push(("segundo_apellido".into(), eq_param(s)));
    }
    
    // Código de centro de votación
    if let Some(s) = q.codigo_centro.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        match s.parse::<i64>() {
            Ok(codigo) => {
                from_where.push_str(" AND CODIGO_NUEVO = :codigo_centro ");
                binds_i64.push(("codigo_centro".into(), codigo));
            }
            Err(_) => {
                return Err(actix_web::error::ErrorBadRequest("codigo_centro inválido (debe ser numérico)"));
            }
        }
    }
    
    // Búsqueda global (en todos los campos)
    if let Some(s) = q.global.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let g = format!("%{}%", s.trim().to_uppercase());
        from_where.push_str(
            " AND (
                NACIONALIDAD LIKE :global
                OR TO_CHAR(CEDULA) LIKE :global
                OR PRIMER_NOMBRE LIKE :global
                OR SEGUNDO_NOMBRE LIKE :global
                OR PRIMER_APELLIDO LIKE :global
                OR SEGUNDO_APELLIDO LIKE :global
                OR FECHA_NACIMIENTO LIKE :global
                OR TO_CHAR(CODIGO_NUEVO) LIKE :global
            ) "
        );
        binds_str.push(("global".into(), g));
    }
    
    // Query optimizado con ROWNUM para paginación
    let sql_select = format!(
        r#"
        SELECT *
        FROM (
            SELECT t_inner.*, ROWNUM rn
            FROM (
                SELECT
                    NACIONALIDAD,
                    CEDULA,
                    PRIMER_NOMBRE,
                    SEGUNDO_NOMBRE,
                    PRIMER_APELLIDO,
                    SEGUNDO_APELLIDO,
                    FECHA_NACIMIENTO,
                    CODIGO_NUEVO AS CODIGO_CENTRO_VOTACION
                {}
                ORDER BY CEDULA
            ) t_inner
            WHERE ROWNUM <= :end_row
        )
        WHERE rn > :offset
        "#,
        from_where
    );
    
    // Preparar parámetros
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
    
    log::info!("🔍 Query get_electores: {}", sql_select);
    
    // Ejecutar query
    let t_select = Instant::now();
    let mut rows_data = conn.query_named(&sql_select, &select_params).map_err(|e| {
        log::error!("❌ Error en SELECT de electores: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error SELECT: {}", e))
    })?;
    log::info!("⏱️ get_electores SELECT ms = {}", t_select.elapsed().as_millis());
    
    // Procesar resultados
    let t_fetch = Instant::now();
    let mut items: Vec<ElectorListaItem> = Vec::new();
    
    while let Some(row) = rows_data.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo filas: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo filas: {}", e))
    })? {
        let nac: String = row.get(0).unwrap_or_else(|_| "V".to_string());
        let ced: i64 = row.get(1).unwrap_or(0);
        let primer_nombre: Option<String> = row.get(2).ok();
        let segundo_nombre: Option<String> = row.get(3).ok();
        let primer_apellido: Option<String> = row.get(4).ok();
        let segundo_apellido: Option<String> = row.get(5).ok();
        let fecha_raw: Option<String> = row.get(6).ok();
        
        // Convertir fecha de YYYYMMDD a YYYY-MM-DD
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
    
    // Determinar si hay más resultados
    let has_more = items.len() as u32 > limit;
    if has_more {
        items.truncate(limit as usize);
    }
    
    log::info!(
        "⏱️ get_electores FETCH rows={} ms = {}",
        items.len(),
        t_fetch.elapsed().as_millis()
    );
    
    Ok(HttpResponse::Ok().json(ElectoresPagedResponse {
        items,
        page,
        limit,
        has_more,
    }))
}
// =====================
// Votos a emitir CON LOGGING
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

// ✅ VOTOS A EMITIR CON LOGGING
pub async fn get_votos_emitir(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    use crate::modules::logging::{extract_ip, extract_user_agent, registrar_log};

    let (nacionalidad_raw, cedula_raw) = path.into_inner();
    let nacionalidad = nacionalidad_raw.trim().to_uppercase();
    let cedula: i64 = cedula_raw.trim().parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("cedula inválida"))?;
    let cedula_int: i32 = cedula as i32;

    log::info!("🔍 Votos Emitir - Cédula: {} {}", nacionalidad, cedula);

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let conn = oracle_conn().map_err(|e| {
        log::error!("❌ Error conectando a Oracle: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e))
    })?;

    let sql_geo = r#"
        SELECT a.centro_votacion, ccv.codigo_nuevo, cv.estado, cv.distrito, cv.municipio
        FROM AC a, CENTRO_VOTACION cv, conversion_centro_votacion ccv
        WHERE a.NACIONALIDAD = :nac AND a.CEDULA = :ced AND a.centro_votacion = cv.codigo
        AND a.centro_votacion = ccv.codigo_actual
    "#;

    let mut rows_geo = conn.query(sql_geo, &[&nacionalidad, &cedula]).map_err(|e| {
        log::error!("❌ Error geo query: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error geo query: {}", e))
    })?;

    let row_geo_opt = rows_geo.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo geo: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo geo: {}", e))
    })?;

    let row_geo = match row_geo_opt {
        Some(r) => r,
        None => {
            log::warn!("⚠️ No se encontró centro de votación para cédula {}", cedula);
            return Ok(HttpResponse::Ok().json(VotosEmitirResponse::default()));
        }
    };

    let cod_estado: i64 = parse_i32_opt(row_geo.get::<usize, Option<String>>(2).ok().flatten()) as i64;
    let cod_municipio: i64 = parse_i32_opt(row_geo.get::<usize, Option<String>>(3).ok().flatten()) as i64;
    let cod_parroq: i64 = parse_i32_opt(row_geo.get::<usize, Option<String>>(4).ok().flatten()) as i64;

    log::info!("📍 Códigos geo - Estado: {}, Municipio: {}, Parroquia: {}", cod_estado, cod_municipio, cod_parroq);

    if cod_estado == 0 || cod_municipio == 0 || cod_parroq == 0 {
        log::warn!("⚠️ Códigos geo inválidos para cédula {}", cedula);
        return Ok(HttpResponse::Ok().json(VotosEmitirResponse::default()));
    }

    let sql_votos = r#"
        SELECT CIRC_CONCEJ, CIRC_ASAMB_LEG, PRESIDENTE, DIP_NOM_ASAMB_NAC, DIP_LIS_ASAMB_NAC,
        DIP_IND_SAMB_NAC, DIP_PARLAM_ANDINO, DIP_PARLAM_LAT_AMER, GOBERNADOR,
        DIP_CONC_LEG_NOM, DIP_CONC_LEG_LIS, REP_IND_CONC_LEG, ALCALD_METROPOL,
        CONC_CAB_METROP_NOM, CONC_CAB_METROP_LIS, ALCALDE_DISTRITAL, CONC_CAB_DIST_NOM,
        CONC_CAB_DIST_LIS, REP_IND_CAB_DIST, ALCALDE_MUNICIPAL, CONC_MUNIC_NOM,
        CONC_MUNIC_LIS, REP_IND_CONC_MUNIC, JUNTA_PARRQ_NOM, JUNTA_PARRQ_LIS, REFERENDOS
        FROM MC.VOTOS_EMITIR
        WHERE cod_estado = :cod_estado AND cod_municipio = :cod_municipio AND cod_parroq = :cod_parroq
    "#;

    let mut rows_v = conn.query(sql_votos, &[&cod_estado, &cod_municipio, &cod_parroq]).map_err(|e| {
        log::error!("❌ Error votos query: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error votos query: {}", e))
    })?;

    let row_v_opt = rows_v.next().transpose().map_err(|e| {
        log::error!("❌ Error leyendo votos: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Error leyendo votos: {}", e))
    })?;

    let r = match row_v_opt {
        Some(x) => x,
        None => {
            log::warn!("⚠️ No hay votos para estado={}, municipio={}, parroquia={}", cod_estado, cod_municipio, cod_parroq);
            return Ok(HttpResponse::Ok().json(VotosEmitirResponse::default()));
        }
    };

    let get_s = |idx: usize| -> i32 {
        parse_i32_opt(r.get::<usize, Option<String>>(idx).ok().flatten())
    };

    let resp = VotosEmitirResponse {
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
    };

    log::info!("✅ Votos a emitir obtenidos exitosamente");

    if let Ok(autor_id) = obtener_id_usuario_del_token(&req, &app_state).await {
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