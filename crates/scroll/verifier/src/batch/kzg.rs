use c_kzg::{KzgSettings, BYTES_PER_G1_POINT, BYTES_PER_G2_POINT, FIELD_ELEMENTS_PER_BLOB};

/// Number of G2 points required for the kzg trusted setup.
/// 65 is fixed and is used for providing multiproofs up to 64 field elements.
pub const NUM_G2_POINTS: usize = 65;

pub const BUILDIN_TRUSTED_SETUP: &[u8] = include_bytes!("kzg_trusted_setup.json");
lazy_static::lazy_static! {
    pub static ref BUILDIN_TRUSTED_SETTING: KzgSettings = build_setting(&BUILDIN_TRUSTED_SETUP).unwrap();
}

#[derive(serde::Deserialize)]
struct TrustedSetup {
    g1_lagrange: Vec<String>,
    g2_monomial: Vec<String>,
}

pub fn build_setting(json_bytes: &[u8]) -> Result<KzgSettings, String> {
    let setup: TrustedSetup =
        serde_json::from_slice(json_bytes).map_err(|err| format!("{:?}", err))?;

    if setup.g1_lagrange.len() != FIELD_ELEMENTS_PER_BLOB {
        return Err(format!(
            "Invalid number of g1 points in trusted setup. Expected {} got {}",
            FIELD_ELEMENTS_PER_BLOB,
            setup.g1_lagrange.len(),
        ));
    }
    if setup.g2_monomial.len() != NUM_G2_POINTS {
        return Err(format!(
            "Invalid number of g2 points in trusted setup. Expected {} got {}",
            NUM_G2_POINTS,
            setup.g2_monomial.len(),
        ));
    }

    let g1 = {
        let mut n = Vec::with_capacity(setup.g1_lagrange.len());
        let mut buf = [0_u8; BYTES_PER_G1_POINT];
        for item in &setup.g1_lagrange {
            let item = item.trim_start_matches("0x");
            let g1_bytes = hex::decode(item).unwrap();
            if g1_bytes.len() != BYTES_PER_G1_POINT {
                return Err(format!(
                    "invalid g1 bytes={}, expected {}",
                    item, BYTES_PER_G1_POINT
                ));
            }
            buf.copy_from_slice(&g1_bytes);
            n.push(buf);
        }
        n
    };
    let g2 = {
        let mut n = Vec::with_capacity(setup.g2_monomial.len());
        let mut buf = [0_u8; BYTES_PER_G2_POINT];
        for item in &setup.g2_monomial {
            let item = item.trim_start_matches("0x");
            let g2_bytes = hex::decode(item).unwrap();
            if g2_bytes.len() != BYTES_PER_G2_POINT {
                return Err(format!(
                    "invalid g2 bytes={}, expected {}",
                    item, BYTES_PER_G2_POINT
                ));
            }
            buf.copy_from_slice(&g2_bytes);
            n.push(buf);
        }
        n
    };

    c_kzg::KzgSettings::load_trusted_setup(&g1, &g2).map_err(|err| err.to_string())
}
