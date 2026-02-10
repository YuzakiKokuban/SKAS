use aes::cipher::{BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use cbc::Encryptor;
use des::cipher::{BlockEncrypt, KeyInit};
use flate2::Compression;
use flate2::GzBuilder;
use md5::{Digest, Md5};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type Aes128Cbc = Encryptor<aes::Aes128>;

const PUBLIC_KEY_B64: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB";

pub fn get_d_id() -> String {
    let uid = Uuid::new_v4().to_string();
    let uid_bytes = uid.as_bytes();

    let mut hasher = Md5::new();
    hasher.update(uid_bytes);
    let binding = hex::encode(hasher.finalize());
    let pri_id = &binding[0..16];

    let pub_key_der = general_purpose::STANDARD.decode(PUBLIC_KEY_B64).unwrap();
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der).unwrap();
    let mut rng = rand::thread_rng();
    let ep_bytes = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, uid_bytes)
        .unwrap();
    let ep = general_purpose::STANDARD.encode(ep_bytes);

    let mut browser = get_browser_env();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    browser.insert("vpw".to_string(), Value::String(Uuid::new_v4().to_string()));
    browser.insert("svm".to_string(), Value::Number(current_time.into()));
    browser.insert(
        "trees".to_string(),
        Value::String(Uuid::new_v4().to_string()),
    );
    browser.insert("pmf".to_string(), Value::Number(current_time.into()));

    let mut des_target = browser.clone();
    des_target.insert("protocol".to_string(), Value::Number(102.into()));
    des_target.insert(
        "organization".to_string(),
        Value::String("UWXspnCCJN4sfYlNfqps".to_string()),
    );
    des_target.insert("appId".to_string(), Value::String("default".to_string()));
    des_target.insert("os".to_string(), Value::String("web".to_string()));
    des_target.insert("version".to_string(), Value::String("3.0.0".to_string()));
    des_target.insert("sdkver".to_string(), Value::String("3.0.0".to_string()));
    des_target.insert("box".to_string(), Value::String("".to_string()));
    des_target.insert("rtype".to_string(), Value::String("all".to_string()));
    des_target.insert("smid".to_string(), Value::String(get_smid()));
    des_target.insert("subVersion".to_string(), Value::String("1.0.0".to_string()));
    des_target.insert("time".to_string(), Value::Number(0.into()));

    let des_target_value = serde_json::to_value(&des_target).unwrap();
    let tn_str = get_tn(&des_target_value);

    let mut tn_hasher = Md5::new();
    tn_hasher.update(tn_str.as_bytes());
    des_target.insert(
        "tn".to_string(),
        Value::String(hex::encode(tn_hasher.finalize())),
    );

    let des_result = des_encrypt_dict(&des_target);
    let gzip_result = gzip_compress(&des_result);
    let aes_result = aes_encrypt(&gzip_result, pri_id);

    let body = serde_json::json!({
        "appId": "default",
        "compress": 2,
        "data": aes_result,
        "encode": 5,
        "ep": ep,
        "organization": "UWXspnCCJN4sfYlNfqps",
        "os": "web"
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://fp-it.portal101.cn/deviceprofile/v4")
        .json(&body)
        .send()
        .unwrap();

    let json: Value = resp.json().unwrap();
    if json["code"].as_i64().unwrap_or(0) != 1100 {
        panic!("did computation failed: {:?}", json);
    }

    format!("B{}", json["detail"]["deviceId"].as_str().unwrap())
}

fn get_smid() -> String {
    let now = chrono::Local::now();
    let time_str = now.format("%Y%m%d%H%M%S").to_string();
    let uid = Uuid::new_v4().to_string();

    let mut hasher = Md5::new();
    hasher.update(uid.as_bytes());
    let md5_uid = hex::encode(hasher.finalize());

    let v = format!("{}{}{}00", time_str, md5_uid, "");

    let mut sm_hasher = Md5::new();
    sm_hasher.update(format!("smsk_web_{}", v).as_bytes());
    let smsk_web = &hex::encode(sm_hasher.finalize())[0..14];

    format!("{}{}{}", v, smsk_web, 0)
}

fn get_browser_env() -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("plugins".to_string(), Value::String("MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1".to_string()));
    map.insert("ua".to_string(), Value::String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0".to_string()));
    map.insert("canvas".to_string(), Value::String("259ffe69".to_string()));
    map.insert("timezone".to_string(), Value::Number((-480).into()));
    map.insert("platform".to_string(), Value::String("Win32".to_string()));
    map.insert(
        "url".to_string(),
        Value::String("https://www.skland.com/".to_string()),
    );
    map.insert("referer".to_string(), Value::String("".to_string()));
    map.insert(
        "res".to_string(),
        Value::String("1920_1080_24_1.25".to_string()),
    );
    map.insert(
        "clientSize".to_string(),
        Value::String("0_0_1080_1920_1920_1080_1920_1080".to_string()),
    );
    map.insert("status".to_string(), Value::String("0011".to_string()));
    map
}

fn get_tn(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut result = String::new();
            for k in keys {
                result.push_str(&get_tn(&map[k]));
            }
            result
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                ((f * 10000.0) as i64).to_string()
            } else {
                String::new()
            }
        }
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn des_encrypt_dict(o: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    let rules = get_des_rules();
    let mut result = BTreeMap::new();

    for (k, v) in o {
        if let Some(rule) = rules.get(k) {
            let val_str = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => v.to_string(),
            };

            let final_val = if rule.is_encrypt {
                let key = rule.key.as_ref().unwrap();
                let des = des::Des::new_from_slice(key.as_bytes()).unwrap();
                let mut data = val_str.into_bytes();
                data.extend_from_slice(&[0u8; 8]);
                let len = data.len();
                let truncated_len = (len / 8) * 8;
                data.truncate(truncated_len);

                let mut output = Vec::new();
                for chunk in data.chunks(8) {
                    let mut block =
                        cbc::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                    des.encrypt_block(&mut block);
                    output.extend_from_slice(&block);
                }
                Value::String(general_purpose::STANDARD.encode(output))
            } else {
                v.clone()
            };
            result.insert(rule.obfuscated_name.clone(), final_val);
        } else {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

struct DesRule {
    is_encrypt: bool,
    key: Option<String>,
    obfuscated_name: String,
}

fn get_des_rules() -> BTreeMap<String, DesRule> {
    let mut m = BTreeMap::new();
    m.insert(
        "appId".into(),
        DesRule {
            is_encrypt: true,
            key: Some("uy7mzc4h".into()),
            obfuscated_name: "xx".into(),
        },
    );
    m.insert(
        "box".into(),
        DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "jf".into(),
        },
    );
    m.insert(
        "canvas".into(),
        DesRule {
            is_encrypt: true,
            key: Some("snrn887t".into()),
            obfuscated_name: "yk".into(),
        },
    );
    m.insert(
        "clientSize".into(),
        DesRule {
            is_encrypt: true,
            key: Some("cpmjjgsu".into()),
            obfuscated_name: "zx".into(),
        },
    );
    m.insert(
        "organization".into(),
        DesRule {
            is_encrypt: true,
            key: Some("78moqjfc".into()),
            obfuscated_name: "dp".into(),
        },
    );
    m.insert(
        "os".into(),
        DesRule {
            is_encrypt: true,
            key: Some("je6vk6t4".into()),
            obfuscated_name: "pj".into(),
        },
    );
    m.insert(
        "platform".into(),
        DesRule {
            is_encrypt: true,
            key: Some("pakxhcd2".into()),
            obfuscated_name: "gm".into(),
        },
    );
    m.insert(
        "plugins".into(),
        DesRule {
            is_encrypt: true,
            key: Some("v51m3pzl".into()),
            obfuscated_name: "kq".into(),
        },
    );
    m.insert(
        "pmf".into(),
        DesRule {
            is_encrypt: true,
            key: Some("2mdeslu3".into()),
            obfuscated_name: "vw".into(),
        },
    );
    m.insert(
        "protocol".into(),
        DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "protocol".into(),
        },
    );
    m.insert(
        "referer".into(),
        DesRule {
            is_encrypt: true,
            key: Some("y7bmrjlc".into()),
            obfuscated_name: "ab".into(),
        },
    );
    m.insert(
        "res".into(),
        DesRule {
            is_encrypt: true,
            key: Some("whxqm2a7".into()),
            obfuscated_name: "hf".into(),
        },
    );
    m.insert(
        "rtype".into(),
        DesRule {
            is_encrypt: true,
            key: Some("x8o2h2bl".into()),
            obfuscated_name: "lo".into(),
        },
    );
    m.insert(
        "sdkver".into(),
        DesRule {
            is_encrypt: true,
            key: Some("9q3dcxp2".into()),
            obfuscated_name: "sc".into(),
        },
    );
    m.insert(
        "status".into(),
        DesRule {
            is_encrypt: true,
            key: Some("2jbrxxw4".into()),
            obfuscated_name: "an".into(),
        },
    );
    m.insert(
        "subVersion".into(),
        DesRule {
            is_encrypt: true,
            key: Some("eo3i2puh".into()),
            obfuscated_name: "ns".into(),
        },
    );
    m.insert(
        "svm".into(),
        DesRule {
            is_encrypt: true,
            key: Some("fzj3kaeh".into()),
            obfuscated_name: "qr".into(),
        },
    );
    m.insert(
        "time".into(),
        DesRule {
            is_encrypt: true,
            key: Some("q2t3odsk".into()),
            obfuscated_name: "nb".into(),
        },
    );
    m.insert(
        "timezone".into(),
        DesRule {
            is_encrypt: true,
            key: Some("1uv05lj5".into()),
            obfuscated_name: "as".into(),
        },
    );
    m.insert(
        "tn".into(),
        DesRule {
            is_encrypt: true,
            key: Some("x9nzj1bp".into()),
            obfuscated_name: "py".into(),
        },
    );
    m.insert(
        "trees".into(),
        DesRule {
            is_encrypt: true,
            key: Some("acfs0xo4".into()),
            obfuscated_name: "pi".into(),
        },
    );
    m.insert(
        "ua".into(),
        DesRule {
            is_encrypt: true,
            key: Some("k92crp1t".into()),
            obfuscated_name: "bj".into(),
        },
    );
    m.insert(
        "url".into(),
        DesRule {
            is_encrypt: true,
            key: Some("y95hjkoo".into()),
            obfuscated_name: "cf".into(),
        },
    );
    m.insert(
        "version".into(),
        DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "version".into(),
        },
    );
    m.insert(
        "vpw".into(),
        DesRule {
            is_encrypt: true,
            key: Some("r9924ab5".into()),
            obfuscated_name: "ca".into(),
        },
    );
    m
}

fn gzip_compress(data: &BTreeMap<String, Value>) -> Vec<u8> {
    let json_str = serde_json::to_string(data).unwrap();
    let mut writer = Vec::new();
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(&mut writer, Compression::default());
    encoder.write_all(json_str.as_bytes()).unwrap();
    encoder.finish().unwrap();
    writer
}

fn aes_encrypt(data: &[u8], key: &str) -> String {
    let iv = b"0102030405060708";
    let key_bytes = key.as_bytes();
    let mut buf = vec![0u8; data.len() + 16];
    buf[..data.len()].copy_from_slice(data);

    let pt_len = data.len();
    let enc = Aes128Cbc::new(key_bytes.into(), iv.into());
    let ct = enc
        .encrypt_padded_mut::<block_padding::ZeroPadding>(&mut buf, pt_len)
        .unwrap();
    hex::encode(ct)
}
