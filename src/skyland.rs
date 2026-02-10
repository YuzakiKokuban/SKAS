use crate::security;
use hmac::{Hmac, Mac};
use md5::Md5;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const APP_CODE: &str = "4ca99fa6b56cc2ba";
const LOGIN_URL: &str = "https://as.hypergryph.com/user/oauth2/v2/grant";
const CRED_URL: &str = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code";
const BINDING_URL: &str = "https://zonai.skland.com/api/v1/game/player/binding";
const ARKNIGHTS_SIGN_URL: &str = "https://zonai.skland.com/api/v1/game/attendance";
const ENDFIELD_SIGN_URL: &str = "https://zonai.skland.com/web/v1/game/endfield/attendance";

pub struct SkylandClient {
    token: String,
    cred: String,
    d_id: String,
    client: reqwest::blocking::Client,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct SignHeader {
    platform: String,
    timestamp: String,
    dId: String,
    vName: String,
}

impl SkylandClient {
    pub fn new(token: String) -> Self {
        let d_id = security::get_d_id();
        let client = reqwest::blocking::Client::builder()
            .user_agent("Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1")
            .build()
            .unwrap();

        let mut sk = SkylandClient {
            token,
            cred: String::new(),
            d_id,
            client,
        };
        sk.login();
        sk
    }

    fn login(&mut self) {
        let body = serde_json::json!({
            "appCode": APP_CODE,
            "token": self.token,
            "type": 0
        });

        let mut headers = HeaderMap::new();
        headers.insert("dId", HeaderValue::from_str(&self.d_id).unwrap());

        let resp = self
            .client
            .post(LOGIN_URL)
            .json(&body)
            .headers(headers.clone())
            .send()
            .unwrap();

        let json: serde_json::Value = resp.json().unwrap();
        if json["status"].as_i64().unwrap_or(-1) != 0 {
            panic!("Login failed: {:?}", json);
        }
        let code = json["data"]["code"].as_str().unwrap();

        let cred_body = serde_json::json!({
            "code": code,
            "kind": 1
        });

        let resp = self
            .client
            .post(CRED_URL)
            .json(&cred_body)
            .headers(headers)
            .send()
            .unwrap();

        let json: serde_json::Value = resp.json().unwrap();
        if json["code"].as_i64().unwrap_or(-1) != 0 {
            panic!("Get cred failed: {:?}", json);
        }

        self.cred = json["data"]["cred"].as_str().unwrap().to_string();
        self.token = json["data"]["token"].as_str().unwrap().to_string();
    }

    fn generate_signature(&self, path: &str, body: &str) -> (String, String) {
        let timestamp = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 2)
        .to_string();

        let header_ca = SignHeader {
            platform: "3".to_string(),
            timestamp: timestamp.clone(),
            dId: self.d_id.clone(),
            vName: "1.0.0".to_string(),
        };

        let header_ca_str = serde_json::to_string(&header_ca).unwrap();
        let s = format!("{}{}{}{}", path, body, timestamp, header_ca_str);

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.token.as_bytes()).unwrap();
        mac.update(s.as_bytes());
        let hex_s = hex::encode(mac.finalize().into_bytes());

        let mut hasher = Md5::new();
        hasher.update(hex_s.as_bytes());
        let sign = hex::encode(hasher.finalize());

        (sign, header_ca_str)
    }

    fn get_headers(&self, path: &str, body: &str) -> HeaderMap {
        let (sign, header_ca_str) = self.generate_signature(path, body);
        let header_ca: HashMap<String, String> = serde_json::from_str(&header_ca_str).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("cred", HeaderValue::from_str(&self.cred).unwrap());
        headers.insert("sign", HeaderValue::from_str(&sign).unwrap());
        headers.insert("dId", HeaderValue::from_str(&self.d_id).unwrap());
        headers.insert("platform", HeaderValue::from_static("3"));
        headers.insert(
            "timestamp",
            HeaderValue::from_str(&header_ca["timestamp"]).unwrap(),
        );
        headers.insert("vName", HeaderValue::from_static("1.0.0"));
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers
    }

    pub fn get_bindings(&self) -> Vec<serde_json::Value> {
        let path = "/api/v1/game/player/binding";
        let headers = self.get_headers(path, "");

        let resp = self
            .client
            .get(BINDING_URL)
            .headers(headers)
            .send()
            .unwrap();

        let json: serde_json::Value = resp.json().unwrap();
        let mut list = Vec::new();

        if let Some(arr) = json["data"]["list"].as_array() {
            for item in arr {
                let app_code = item["appCode"].as_str().unwrap_or("");
                if let Some(bindings) = item["bindingList"].as_array() {
                    for binding in bindings {
                        let mut b = binding.clone();
                        b["appCode"] = serde_json::json!(app_code);
                        list.push(b);
                    }
                }
            }
        }
        list
    }

    pub fn sign_arknights(&self, binding: &serde_json::Value) {
        let path = "/api/v1/game/attendance";
        let body = serde_json::json!({
            "gameId": binding["gameId"],
            "uid": binding["uid"]
        });
        let body_str = body.to_string();
        let headers = self.get_headers(path, &body_str);

        let resp = self
            .client
            .post(ARKNIGHTS_SIGN_URL)
            .headers(headers)
            .body(body_str)
            .send()
            .unwrap();

        println!("Arknights Sign: {:?}", resp.text().unwrap());
    }

    pub fn sign_endfield(&self, binding: &serde_json::Value) {
        if let Some(roles) = binding["roles"].as_array() {
            for role in roles {
                let path = "/web/v1/game/endfield/attendance";
                let headers = self.get_headers(path, "");
                let mut h = headers.clone();

                let role_id = role["roleId"].as_str().unwrap();
                let server_id = role["serverId"].as_str().unwrap();
                h.insert(
                    "sk-game-role",
                    HeaderValue::from_str(&format!("3_{}_{}", role_id, server_id)).unwrap(),
                );

                let resp = self
                    .client
                    .post(ENDFIELD_SIGN_URL)
                    .headers(h)
                    .body("{}")
                    .send()
                    .unwrap();
                println!("Endfield Sign: {:?}", resp.text().unwrap());
            }
        }
    }
}
