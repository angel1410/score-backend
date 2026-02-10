use actix_web::{web, HttpResponse, Error};
use oracle::{Connection, Row, RowValue};
use serde::Deserialize;
use std::env;

// =====================
// Movimiento RE (tu código)
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

pub async fn get_movimientos_re(
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    let (nacionalidad, cedula) = path.into_inner();
    let nacionalidad = nacionalidad.to_uppercase();

    let conn = oracle_conn()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e)))?;

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

    let rows = conn.query_as::<MovimientoRE>(sql, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error ejecutando query: {}", e)))?;

    let mut re_array: Vec<MovimientoRE> = Vec::new();
    for row_result in rows {
        let mov = row_result
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error procesando fila: {}", e)))?;
        re_array.push(mov);
    }

    Ok(HttpResponse::Ok().json(&re_array))
}

// =====================
// Elector (para tu Dialog)
// =====================

#[derive(Deserialize)]
pub struct ElectorQuery {
    pub nacionalidad: String, // V / E
    pub cedula: i64,          // 28524669
}

#[derive(serde::Serialize, Default)]
pub struct ElectorResponse {
    // Sección 1
    pub nacionalidad: String,
    pub cedula: i64,
    pub fecha_nacimiento: Option<String>, // YYYY-MM-DD
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub codigo_objecion: Option<String>,
    pub descripcion_objecion: Option<String>,

    // Sección 2
    pub fecha_ultimo_evento: Option<String>, // YYYY-MM-DD
    pub edad_ultimo_evento: Option<i64>,
    pub numero_mesa: Option<i64>,
    pub numero_pagina: Option<i64>,
    pub numero_renglon: Option<i64>,

    pub codigo_centro: Option<String>, // ✅ SIEMPRE 9 dígitos
    pub estado: Option<String>,
    pub municipio: Option<String>,
    pub parroquia: Option<String>,
    pub nombre_centro: Option<String>,
    pub direccion_centro: Option<String>,

    // ✅ Sección 3 (compatibles con el front)
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

// ✅ helper: siempre 9 dígitos
fn pad9(n: i64) -> String {
    format!("{:09}", n)
}

// ==== Helpers geo ====

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

    t = t.trim_start_matches(|c: char| c == '-' || c == '—' || c == ':' ).trim().to_string();
    t
}

// ✅ Formato final: "13 - MIRANDA" / "08 - PLAZA" / "01 - GUARENAS"
fn fmt_geo(code: i64, desc: Option<String>) -> String {
    let code2 = format!("{:02}", code);
    let d = desc.map(clean_geo_desc).unwrap_or_else(|| "NO DEFINIDO".to_string());
    format!("{code2} - {d}")
}

// ==== Helpers miembro de mesa ====

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

// GET /api/get_elector?nacionalidad=V&cedula=28524669
pub async fn get_elector(
    query: web::Query<ElectorQuery>,
) -> Result<HttpResponse, Error> {
    let nac = query.nacionalidad.trim().to_uppercase();
    let nacionalidad = nac.chars().next().unwrap_or('V').to_string();
    let cedula = query.cedula;

    if !(nacionalidad == "V" || nacionalidad == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let conn = oracle_conn()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e)))?;

    let mut resp = ElectorResponse {
        nacionalidad: nacionalidad.clone(),
        cedula,
        ..Default::default()
    };

    // ---------------------
    // 1) AC + OBJECION
    // ---------------------
    let sql_persona = r#"
        SELECT
          AC.PRIMER_APELLIDO,
          AC.SEGUNDO_APELLIDO,
          AC.PRIMER_NOMBRE,
          AC.SEGUNDO_NOMBRE,
          AC.FECHA_NACIMIENTO_4,
          AC.STATUS_OBJECION,
          OBJ.DESCRIPCION
        FROM AC AC
        JOIN OBJECION OBJ ON AC.STATUS_OBJECION = OBJ.STATUS
        WHERE AC.NACIONALIDAD = :nacionalidad
          AND AC.CEDULA = :cedula
    "#;

    let mut rows = conn.query(sql_persona, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query persona: {}", e)))?;

    let row_opt = rows.next().transpose()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo persona: {}", e)))?;

    let row = match row_opt {
        Some(r) => r,
        None => return Ok(HttpResponse::NotFound().body("Elector no encontrado")),
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

    // ---------------------
    // 2) instrumentos.cuaderno_actual2
    // ---------------------
    let sql_cuaderno = r#"
        SELECT
          nu_mesa,
          nu_pagina,
          nu_renglon,
          nu_edad_al_evento,
          fe_evento,
          cod_estado,
          cod_municipio,
          cod_parroquia,
          nu_centro
        FROM instrumentos.cuaderno_actual2
        WHERE co_nacionalidad = :nacionalidad
          AND nu_cedula = :cedula
    "#;

    let mut rows2 = conn.query(sql_cuaderno, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query cuaderno: {}", e)))?;

    let row2_opt = rows2.next().transpose()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo cuaderno: {}", e)))?;

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

            // ✅ aquí el cambio: código centro SIEMPRE con 9 dígitos
            resp.codigo_centro = cc.map(pad9);

            (ce, cm, cp, cc)
        } else {
            (None, None, None, None)
        };

    // 2.1) Vista geográfica
    if let (Some(ce), Some(cm), Some(cp), Some(cc)) = (cod_estado, cod_municipio, cod_parroquia, cod_centro) {
        let sql_geo = r#"
            SELECT
              COD_ESTADO,
              DES_ESTADO,
              COD_MUNICIPIO,
              DES_MUNICIPIO,
              COD_PARROQUIA,
              DES_PARROQUIA,
              CODIGO_NUEVO,
              NOMBRE,
              DIRECCION
            FROM RE.V_CENTRO_VOTACION_GEOGRAFICO
            WHERE CODIGO_NUEVO  = :cc
              AND COD_ESTADO    = :ce
              AND COD_MUNICIPIO = :cm
              AND COD_PARROQUIA = :cp
        "#;

        let mut rows3 = conn.query(sql_geo, &[&cc, &ce, &cm, &cp])
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query vista geografica: {}", e)))?;

        if let Some(r3) = rows3.next().transpose()
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo vista geografica: {}", e)))? {

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

    // ---------------------
    // 3) Miembro de mesa
    // ---------------------
    set_no_aplica_miembro(&mut resp);

    let sql_miembro = r#"
        SELECT
          miembro.mesa,
          cargo_miembro.descripcion_cargo,
          miembro.centrocap,
          c_capacitacion.nombre,
          miembro.tallerdesde,
          miembro.tallerhasta,
          miembro.horario,
          c_capacitacion.direccion
        FROM miembros_oes miembro,
             cargos_miembros_oes cargo_miembro,
             tipos_oes t_oes,
             MC.centro_capacitacion c_capacitacion
        WHERE t_oes.tipo_oes = cargo_miembro.tipo_oes
          AND cargo_miembro.tipo_oes = miembro.timioes
          AND miembro.cargo = cargo_miembro.cod_cargo
          AND miembro.centrocap = c_capacitacion.codigo
          AND miembro.nac = :nacionalidad
          AND miembro.cedula = :cedula
    "#;

    let mut rowsm = conn.query(sql_miembro, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query miembro_mesa: {}", e)))?;

    if let Some(rm) = rowsm.next().transpose()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo miembro_mesa: {}", e)))? {

        let mesa: Option<i64> = rm.get(0).ok();
        resp.miembro_mesa_numero_mesa = Some(mesa.unwrap_or(0));

        resp.miembro_mesa_cargo = rm.get(1).ok();

        let centrocap: Option<String> = rm.get(2).ok();
        resp.miembro_mesa_centro_capacitacion = Some(centrocap.unwrap_or_else(|| "0".to_string()));

        resp.miembro_mesa_nombre_centro_capacitacion = rm.get(3).ok();

        let desde: Option<String> = rm.get(4).ok();
        resp.miembro_mesa_fecha_inicio_capacitacion =
            desde.as_deref().and_then(ddmmyyyy).or(Some("No aplica".to_string()));

        let hasta: Option<String> = rm.get(5).ok();
        resp.miembro_mesa_fecha_culminacion_capacitacion =
            hasta.as_deref().and_then(ddmmyyyy).or(Some("No aplica".to_string()));

        let horario: Option<String> = rm.get(6).ok();
        resp.miembro_mesa_horario_capacitacion =
            horario.as_deref().and_then(fmt_horario).or(Some("No aplica".to_string()));

        resp.miembro_mesa_direccion_centro_capacitacion = rm.get(7).ok();
    }

    Ok(HttpResponse::Ok().json(resp))
}
