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
// NUEVO: Elector (para tu Dialog)
// =====================

#[derive(Deserialize)]
pub struct ElectorQuery {
    pub nac: String,     // V / E
    pub cedula: i64,     // 28524669
}

#[derive(serde::Serialize, Default)]
pub struct ElectorResponse {
    // Sección 1
    pub nacionalidad: String,
    pub cedula: i64,
    pub fecha_nacimiento: Option<String>,     // YYYY-MM-DD
    pub primer_nombre: Option<String>,
    pub segundo_nombre: Option<String>,
    pub primer_apellido: Option<String>,
    pub segundo_apellido: Option<String>,
    pub codigo_objecion: Option<String>,      // lo devolvemos string (como tu TS)
    pub descripcion_objecion: Option<String>,

    // Sección 2
    pub fecha_ultimo_evento: Option<String>,  // YYYY-MM-DD
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
}

fn yyyymmdd_to_iso(s: &str) -> Option<String> {
    if s.len() < 8 { return None; }
    Some(format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]))
}

// GET /api/re/elector?nac=V&cedula=28524669
pub async fn get_elector(
    query: web::Query<ElectorQuery>,
) -> Result<HttpResponse, Error> {
    let nac = query.nac.trim().to_uppercase();
    let nac_char = nac.chars().next().unwrap_or('V').to_string();
    let cedula = query.cedula;

    if !(nac_char == "V" || nac_char == "E") {
        return Err(actix_web::error::ErrorBadRequest("nac debe ser V o E"));
    }
    if cedula <= 0 || cedula > 99_999_999 {
        return Err(actix_web::error::ErrorBadRequest("cedula inválida"));
    }

    let conn = oracle_conn()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e)))?;

    let mut resp = ElectorResponse {
        nacionalidad: nac_char.clone(),
        cedula,
        ..Default::default()
    };

    // 1) AC + OBJECION (datos personales)
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
        WHERE AC.NACIONALIDAD = :nac
          AND AC.CEDULA = :ced
    "#;

    let mut rows = conn.query(sql_persona, &[&nac_char, &cedula])
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

    // 2) instrumentos.cuaderno_actual2 (identificación electoral)
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
        WHERE co_nacionalidad = :nac
          AND nu_cedula = :ced
    "#;

    let mut rows2 = conn.query(sql_cuaderno, &[&nac_char, &cedula])
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

            resp.codigo_centro = cc.map(|x| x.to_string());

            (ce, cm, cp, cc)
        } else {
            (None, None, None, None)
        };

    // 3) Estado/Municipio/Parroquia + centro (si tenemos códigos)
    if let (Some(ce), Some(cm), Some(cp), Some(cc)) = (cod_estado, cod_municipio, cod_parroquia, cod_centro) {
        let sql_centro = r#"
            SELECT
              e.des_estado,
              m.des_municipio,
              p.des_parroquia,
              c.nombre,
              c.direccion
            FROM estado e
            JOIN municipio m ON m.cod_estado = e.cod_estado
            JOIN parroquia p ON p.cod_estado = e.cod_estado AND p.cod_municipio = m.cod_municipio
            JOIN centro_votacion c
              ON c.estado = p.cod_estado AND c.distrito = p.cod_municipio AND c.municipio = p.cod_parroquia
            WHERE e.cod_estado = :ce
              AND m.cod_municipio = :cm
              AND p.cod_parroquia = :cp
              AND c.codigo = :cc
        "#;

        let mut rows3 = conn.query(sql_centro, &[&ce, &cm, &cp, &cc])
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error query centro: {}", e)))?;

        if let Some(r3) = rows3.next().transpose()
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error leyendo centro: {}", e)))? {
            resp.estado = r3.get(0).ok();
            resp.municipio = r3.get(1).ok();
            resp.parroquia = r3.get(2).ok();
            resp.nombre_centro = r3.get(3).ok();
            resp.direccion_centro = r3.get(4).ok();
        }
    }

    Ok(HttpResponse::Ok().json(resp))
}
