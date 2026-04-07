// Copyright 2026 YuzakiKokuban
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::Encryptor as CbcEncryptor;
use chrono::Local;
use ecb::cipher::block_padding::NoPadding;
use ecb::cipher::{BlockEncryptMut, KeyInit, KeyIvInit};
use des::TdesEde3;
use ecb::Encryptor as EcbEncryptor;
use flate2::Compression;
use flate2::GzBuilder;
use reqwest::blocking::Client;
use rsa::rand_core::OsRng;
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt, pkcs8::DecodePublicKey};
use serde_json::{Map, Number, Value};
use uuid::Uuid;

use crate::utils::{md5_hex, object_from_pairs, python_json_string};

const DEVICES_INFO_URL: &str = "https://fp-it.portal101.cn/deviceprofile/v4";
const SM_ORGANIZATION: &str = "UWXspnCCJN4sfYlNfqps";
const SM_APP_ID: &str = "default";
const SM_PUBLIC_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB";

type TdesEcbEnc = EcbEncryptor<TdesEde3>;
type AesCbcEnc = CbcEncryptor<Aes128>;

#[derive(Clone, Copy)]
struct DesRule {
    is_encrypt: bool,
    key: Option<&'static str>,
    obfuscated_name: &'static str,
}

fn des_rule(key: &str) -> Option<DesRule> {
    Some(match key {
        "appId" => DesRule {
            is_encrypt: true,
            key: Some("uy7mzc4h"),
            obfuscated_name: "xx",
        },
        "box" => DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "jf",
        },
        "canvas" => DesRule {
            is_encrypt: true,
            key: Some("snrn887t"),
            obfuscated_name: "yk",
        },
        "clientSize" => DesRule {
            is_encrypt: true,
            key: Some("cpmjjgsu"),
            obfuscated_name: "zx",
        },
        "organization" => DesRule {
            is_encrypt: true,
            key: Some("78moqjfc"),
            obfuscated_name: "dp",
        },
        "os" => DesRule {
            is_encrypt: true,
            key: Some("je6vk6t4"),
            obfuscated_name: "pj",
        },
        "platform" => DesRule {
            is_encrypt: true,
            key: Some("pakxhcd2"),
            obfuscated_name: "gm",
        },
        "plugins" => DesRule {
            is_encrypt: true,
            key: Some("v51m3pzl"),
            obfuscated_name: "kq",
        },
        "pmf" => DesRule {
            is_encrypt: true,
            key: Some("2mdeslu3"),
            obfuscated_name: "vw",
        },
        "protocol" => DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "protocol",
        },
        "referer" => DesRule {
            is_encrypt: true,
            key: Some("y7bmrjlc"),
            obfuscated_name: "ab",
        },
        "res" => DesRule {
            is_encrypt: true,
            key: Some("whxqm2a7"),
            obfuscated_name: "hf",
        },
        "rtype" => DesRule {
            is_encrypt: true,
            key: Some("x8o2h2bl"),
            obfuscated_name: "lo",
        },
        "sdkver" => DesRule {
            is_encrypt: true,
            key: Some("9q3dcxp2"),
            obfuscated_name: "sc",
        },
        "status" => DesRule {
            is_encrypt: true,
            key: Some("2jbrxxw4"),
            obfuscated_name: "an",
        },
        "subVersion" => DesRule {
            is_encrypt: true,
            key: Some("eo3i2puh"),
            obfuscated_name: "ns",
        },
        "svm" => DesRule {
            is_encrypt: true,
            key: Some("fzj3kaeh"),
            obfuscated_name: "qr",
        },
        "time" => DesRule {
            is_encrypt: true,
            key: Some("q2t3odsk"),
            obfuscated_name: "nb",
        },
        "timezone" => DesRule {
            is_encrypt: true,
            key: Some("1uv05lj5"),
            obfuscated_name: "as",
        },
        "tn" => DesRule {
            is_encrypt: true,
            key: Some("x9nzj1bp"),
            obfuscated_name: "py",
        },
        "trees" => DesRule {
            is_encrypt: true,
            key: Some("acfs0xo4"),
            obfuscated_name: "pi",
        },
        "ua" => DesRule {
            is_encrypt: true,
            key: Some("k92crp1t"),
            obfuscated_name: "bj",
        },
        "url" => DesRule {
            is_encrypt: true,
            key: Some("y95hjkoo"),
            obfuscated_name: "cf",
        },
        "version" => DesRule {
            is_encrypt: false,
            key: None,
            obfuscated_name: "version",
        },
        "vpw" => DesRule {
            is_encrypt: true,
            key: Some("r9924ab5"),
            obfuscated_name: "ca",
        },
        _ => return None,
    })
}

fn browser_env() -> Value {
    object_from_pairs([
        (
            "plugins",
            Value::String("MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1".to_string()),
        ),
        (
            "ua",
            Value::String(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0".to_string(),
            ),
        ),
        ("canvas", Value::String("259ffe69".to_string())),
        ("timezone", Value::Number(Number::from(-480))),
        ("platform", Value::String("Win32".to_string())),
        ("url", Value::String("https://www.skland.com/".to_string())),
        ("referer", Value::String(String::new())),
        ("res", Value::String("1920_1080_24_1.25".to_string())),
        ("clientSize", Value::String("0_0_1080_1920_1920_1080_1920_1080".to_string())),
        ("status", Value::String("0011".to_string())),
    ])
}

fn triple_des_encrypt_base64(value: &str, key: &str) -> Result<String> {
    let mut expanded_key = Vec::with_capacity(24);
    expanded_key.extend_from_slice(key.as_bytes());
    expanded_key.extend_from_slice(key.as_bytes());
    expanded_key.extend_from_slice(key.as_bytes());

    let mut data = value.as_bytes().to_vec();
    let pad_len = (8 - data.len() % 8) % 8;
    if pad_len > 0 {
        data.extend(std::iter::repeat_n(0_u8, pad_len));
    }

    let msg_len = data.len();
    let cipher =
        TdesEcbEnc::new_from_slice(&expanded_key).context("failed to build 3DES cipher")?;
    let encrypted = cipher
        .encrypt_padded_mut::<NoPadding>(&mut data, msg_len)
        .map_err(|_| anyhow!("failed to encrypt 3DES payload"))?;
    Ok(STANDARD.encode(encrypted))
}

fn aes_encrypt_hex(value: &[u8], key: &[u8]) -> Result<String> {
    let mut data = value.to_vec();
    data.push(0_u8);
    while data.len() % 16 != 0 {
        data.push(0_u8);
    }

    let msg_len = data.len();
    let iv = b"0102030405060708";
    let cipher = AesCbcEnc::new_from_slices(key, iv).context("failed to build AES cipher")?;
    let encrypted = cipher
        .encrypt_padded_mut::<NoPadding>(&mut data, msg_len)
        .map_err(|_| anyhow!("failed to encrypt AES payload"))?;
    Ok(hex::encode(encrypted))
}

fn gzip_base64(value: &Value) -> Result<Vec<u8>> {
    let json = python_json_string(value);
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::new(2));
    encoder
        .write_all(json.as_bytes())
        .context("failed to write gzip data")?;
    let compressed = encoder.finish().context("failed to finish gzip stream")?;
    Ok(STANDARD.encode(compressed).into_bytes())
}

fn get_tn_map(map: &Map<String, Value>) -> String {
    let mut keys = map.keys().cloned().collect::<Vec<_>>();
    keys.sort();

    let mut result = String::new();
    for key in keys {
        let value = map.get(&key).unwrap_or(&Value::Null);
        let piece = match value {
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    (value * 10_000).to_string()
                } else if let Some(value) = number.as_u64() {
                    (value * 10_000).to_string()
                } else if let Some(value) = number.as_f64() {
                    (value * 10_000.0).to_string()
                } else {
                    number.to_string()
                }
            }
            Value::Object(inner) => get_tn_map(inner),
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Null => "null".to_string(),
            Value::Array(values) => values
                .iter()
                .map(python_json_string)
                .collect::<Vec<_>>()
                .join(""),
        };
        result.push_str(&piece);
    }

    result
}

fn get_smid() -> String {
    let time_part = Local::now().format("%Y%m%d%H%M%S").to_string();
    let uid = Uuid::new_v4().to_string();
    let base = format!("{time_part}{}00", md5_hex(uid));
    let suffix = md5_hex(format!("smsk_web_{base}"));
    format!("{base}{}0", &suffix[..14])
}

fn des_transform(map: &Map<String, Value>) -> Result<Value> {
    let mut result = Map::new();

    for (key, value) in map {
        if let Some(rule) = des_rule(key) {
            let transformed = if rule.is_encrypt {
                let key = rule.key.context("missing DES rule key")?;
                let raw = match value {
                    Value::String(value) => value.clone(),
                    other => python_json_string(other).trim_matches('"').to_string(),
                };
                Value::String(triple_des_encrypt_base64(&raw, key)?)
            } else {
                value.clone()
            };
            result.insert(rule.obfuscated_name.to_string(), transformed);
        } else {
            result.insert(key.clone(), value.clone());
        }
    }

    Ok(Value::Object(result))
}

pub fn get_d_id(http: &Client) -> Result<String> {
    let uid = Uuid::new_v4().to_string().into_bytes();
    let pri_id = md5_hex(&uid)[..16].to_string();

    let public_key_der = STANDARD
        .decode(SM_PUBLIC_KEY)
        .context("invalid RSA public key")?;
    let public_key = RsaPublicKey::from_public_key_der(&public_key_der)
        .context("failed to parse RSA public key")?;
    let encrypted_uid = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &uid)
        .context("failed to encrypt device payload")?;
    let ep = STANDARD.encode(encrypted_uid);

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_millis() as i64;

    let mut browser = match browser_env() {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    browser.insert("vpw".to_string(), Value::String(Uuid::new_v4().to_string()));
    browser.insert("svm".to_string(), Value::Number(Number::from(current_time)));
    browser.insert(
        "trees".to_string(),
        Value::String(Uuid::new_v4().to_string()),
    );
    browser.insert("pmf".to_string(), Value::Number(Number::from(current_time)));

    let mut target = Map::new();
    for (key, value) in browser {
        target.insert(key, value);
    }
    target.insert("protocol".to_string(), Value::Number(Number::from(102)));
    target.insert(
        "organization".to_string(),
        Value::String(SM_ORGANIZATION.to_string()),
    );
    target.insert("appId".to_string(), Value::String(SM_APP_ID.to_string()));
    target.insert("os".to_string(), Value::String("web".to_string()));
    target.insert("version".to_string(), Value::String("3.0.0".to_string()));
    target.insert("sdkver".to_string(), Value::String("3.0.0".to_string()));
    target.insert("box".to_string(), Value::String(String::new()));
    target.insert("rtype".to_string(), Value::String("all".to_string()));
    target.insert("smid".to_string(), Value::String(get_smid()));
    target.insert("subVersion".to_string(), Value::String("1.0.0".to_string()));
    target.insert("time".to_string(), Value::Number(Number::from(0)));

    let tn = md5_hex(get_tn_map(&target));
    target.insert("tn".to_string(), Value::String(tn));

    let transformed = des_transform(&target)?;
    let compressed = gzip_base64(&transformed)?;
    let data = aes_encrypt_hex(&compressed, pri_id.as_bytes())?;

    let body = object_from_pairs([
        ("appId", Value::String(SM_APP_ID.to_string())),
        ("compress", Value::Number(Number::from(2))),
        ("data", Value::String(data)),
        ("encode", Value::Number(Number::from(5))),
        ("ep", Value::String(ep)),
        ("organization", Value::String(SM_ORGANIZATION.to_string())),
        ("os", Value::String("web".to_string())),
    ]);

    let response = http
        .post(DEVICES_INFO_URL)
        .header("Content-Type", "application/json")
        .body(python_json_string(&body))
        .send()
        .context("failed to request device profile")?;

    let response_json = response
        .json::<Value>()
        .context("invalid device profile response")?;
    if response_json.get("code").and_then(Value::as_i64) != Some(1100) {
        return Ok(String::new());
    }

    let device_id = response_json
        .get("detail")
        .and_then(Value::as_object)
        .and_then(|detail| detail.get("deviceId"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    Ok(format!("B{device_id}"))
}
