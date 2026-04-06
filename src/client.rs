// Copyright 2026 YuzakiKokuban
// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use hmac::{Hmac, Mac};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use sha2::Sha256;

use crate::security::get_d_id;
use crate::utils::{md5_hex, object_from_pairs, python_json_string};

type HmacSha256 = Hmac<Sha256>;

const APP_CODE: &str = "4ca99fa6b56cc2ba";
const GRANT_CODE_URL: &str = "https://as.hypergryph.com/user/oauth2/v2/grant";
const CRED_CODE_URL: &str = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code";
const BINDING_URL: &str = "https://zonai.skland.com/api/v1/game/player/binding";
const ARKNIGHTS_SIGN_URL: &str = "https://zonai.skland.com/api/v1/game/attendance";
const ENDFIELD_SIGN_URL: &str = "https://zonai.skland.com/web/v1/game/endfield/attendance";
const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 12; SKAS/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36";

#[derive(Clone, Debug)]
pub struct Character {
    pub app_code: String,
    pub display_name: String,
    pub game_id: Option<String>,
    pub uid: Option<String>,
    pub role_id: Option<String>,
    pub server_id: Option<String>,
}

pub struct SkylandClient {
    token: String,
    d_id: String,
    cred: Option<String>,
    cred_token: Option<String>,
    http: Client,
}

struct SignatureHeaders {
    sign: String,
    timestamp: String,
}

impl SkylandClient {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .use_rustls_tls()
            .gzip(true)
            .build()
            .context("failed to build HTTP client")?;

        let d_id = get_d_id(&http)?;
        Ok(Self {
            token: token.into(),
            d_id,
            cred: None,
            cred_token: None,
            http,
        })
    }

    pub fn run_sign(&mut self, enable_games: &[String]) -> (bool, Vec<String>) {
        let mut logs = Vec::new();
        let mut all_success = true;

        let result = (|| -> Result<()> {
            self.login()?;
            for character in self.get_bindings()? {
                if !enable_games.is_empty()
                    && !enable_games.iter().any(|game| game == &character.app_code)
                {
                    continue;
                }

                let sign_result = match character.app_code.as_str() {
                    "arknights" => self.sign_arknights(&character),
                    "endfield" => self.sign_endfield(&character),
                    _ => continue,
                };

                match sign_result {
                    Ok(result) => {
                        let code = result.get("code").and_then(Value::as_i64).unwrap_or(-1);
                        let msg = result
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("OK");

                        let status = if code == 0 {
                            "SUCCESS"
                        } else if msg.contains("重复") {
                            "INFO"
                        } else {
                            all_success = false;
                            "FAIL"
                        };

                        let awards = result
                            .get("data")
                            .and_then(Value::as_object)
                            .and_then(|data| data.get("awards"))
                            .and_then(Value::as_array)
                            .map(|awards| {
                                let rendered = awards
                                    .iter()
                                    .filter_map(|award| {
                                        let resource_name = award
                                            .get("resource")
                                            .and_then(Value::as_object)
                                            .and_then(|resource| resource.get("name"))
                                            .and_then(Value::as_str)?;
                                        let count = award.get("count")?;
                                        Some(format!(
                                            "{resource_name}x{}",
                                            render_plain_value(count)
                                        ))
                                    })
                                    .collect::<Vec<_>>();
                                if rendered.is_empty() {
                                    String::new()
                                } else {
                                    format!(" | 获得: {}", rendered.join(","))
                                }
                            })
                            .unwrap_or_default();

                        logs.push(format!(
                            "[{}] {}: {} - {}{}",
                            character.app_code.to_uppercase(),
                            character.display_name,
                            status,
                            msg,
                            awards
                        ));
                    }
                    Err(error) => {
                        all_success = false;
                        logs.push(format!(
                            "[{}] {}: ERROR - {}",
                            character.app_code.to_uppercase(),
                            character.display_name,
                            error
                        ));
                    }
                }
            }
            Ok(())
        })();

        if let Err(error) = result {
            all_success = false;
            logs.push(format!("Login/Init Error: {error}"));
        }

        (all_success, logs)
    }

    fn login(&mut self) -> Result<()> {
        let grant_body = object_from_pairs([
            ("appCode", Value::String(APP_CODE.to_string())),
            ("token", Value::String(self.token.clone())),
            ("type", Value::Number(0.into())),
        ]);
        let grant_response = self
            .http
            .post(GRANT_CODE_URL)
            .headers(self.base_headers()?)
            .header("Content-Type", "application/json")
            .body(python_json_string(&grant_body))
            .send()
            .context("failed to request OAuth grant")?
            .json::<Value>()
            .context("invalid OAuth grant response")?;

        if grant_response.get("status").and_then(Value::as_i64) != Some(0) {
            let message = grant_response
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(anyhow!("OAuth Grant failed: {message}"));
        }

        let grant_code = grant_response
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get("code"))
            .and_then(Value::as_str)
            .context("missing OAuth grant code")?;

        let cred_body = object_from_pairs([
            ("code", Value::String(grant_code.to_string())),
            ("kind", Value::Number(1.into())),
        ]);
        let cred_response = self
            .http
            .post(CRED_CODE_URL)
            .headers(self.base_headers()?)
            .header("Content-Type", "application/json")
            .body(python_json_string(&cred_body))
            .send()
            .context("failed to request cred")?
            .json::<Value>()
            .context("invalid cred response")?;

        if cred_response.get("code").and_then(Value::as_i64) != Some(0) {
            let message = cred_response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(anyhow!("Get Cred failed: {message}"));
        }

        let data = cred_response
            .get("data")
            .and_then(Value::as_object)
            .context("missing cred payload")?;

        self.cred = data
            .get("cred")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        self.cred_token = data
            .get("token")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        Ok(())
    }

    fn get_bindings(&self) -> Result<Vec<Character>> {
        let response = self
            .http
            .get(BINDING_URL)
            .headers(self.sign_headers(BINDING_URL, "get", None)?)
            .send()
            .context("failed to request bindings")?
            .json::<Value>()
            .context("invalid bindings response")?;

        if response.get("code").and_then(Value::as_i64) != Some(0) {
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(anyhow!("Get bindings failed: {message}"));
        }

        let mut bindings = Vec::new();
        let apps = response
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get("list"))
            .and_then(Value::as_array)
            .context("missing binding list")?;

        for app in apps {
            let Some(app_code) = app.get("appCode").and_then(Value::as_str) else {
                continue;
            };
            if app_code != "arknights" && app_code != "endfield" {
                continue;
            }

            let Some(binding_list) = app.get("bindingList").and_then(Value::as_array) else {
                continue;
            };

            match app_code {
                "arknights" => {
                    for item in binding_list {
                        let Some(item_map) = item.as_object() else {
                            continue;
                        };
                        bindings.push(Character {
                            app_code: app_code.to_string(),
                            display_name: item_map
                                .get("nickName")
                                .and_then(Value::as_str)
                                .or_else(|| item_map.get("uid").and_then(Value::as_str))
                                .unwrap_or("Unknown")
                                .to_string(),
                            game_id: item_map.get("gameId").map(render_plain_value),
                            uid: item_map.get("uid").map(render_plain_value),
                            role_id: None,
                            server_id: None,
                        });
                    }
                }
                "endfield" => {
                    for item in binding_list {
                        let Some(item_map) = item.as_object() else {
                            continue;
                        };
                        let Some(roles) = item_map.get("roles").and_then(Value::as_array) else {
                            continue;
                        };
                        for role in roles {
                            let Some(role_map) = role.as_object() else {
                                continue;
                            };
                            bindings.push(Character {
                                app_code: app_code.to_string(),
                                display_name: role_map
                                    .get("nickname")
                                    .and_then(Value::as_str)
                                    .or_else(|| role_map.get("roleId").and_then(Value::as_str))
                                    .unwrap_or("Unknown")
                                    .to_string(),
                                game_id: None,
                                uid: None,
                                role_id: role_map.get("roleId").map(render_plain_value),
                                server_id: role_map.get("serverId").map(render_plain_value),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(bindings)
    }

    fn sign_arknights(&self, character: &Character) -> Result<Value> {
        let body = object_from_pairs([
            (
                "gameId",
                Value::String(character.game_id.clone().context("missing gameId")?),
            ),
            (
                "uid",
                Value::String(character.uid.clone().context("missing uid")?),
            ),
        ]);
        let body_string = python_json_string(&body);
        let response = self
            .http
            .post(ARKNIGHTS_SIGN_URL)
            .headers(self.sign_headers(ARKNIGHTS_SIGN_URL, "post", Some(&body_string))?)
            .header("Content-Type", "application/json")
            .body(body_string)
            .send()
            .context("failed to request Arknights sign")?
            .json::<Value>()
            .context("invalid Arknights sign response")?;
        Ok(response)
    }

    fn sign_endfield(&self, character: &Character) -> Result<Value> {
        let mut headers = self.sign_headers(ENDFIELD_SIGN_URL, "post", Some(""))?;
        let role = format!(
            "3_{}_{}",
            character.role_id.clone().context("missing roleId")?,
            character.server_id.clone().context("missing serverId")?,
        );
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert(
            "sk-game-role",
            HeaderValue::from_str(&role).context("invalid sk-game-role header")?,
        );

        let response = self
            .http
            .post(ENDFIELD_SIGN_URL)
            .headers(headers)
            .send()
            .context("failed to request Endfield sign")?
            .json::<Value>()
            .context("invalid Endfield sign response")?;
        Ok(response)
    }

    fn base_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", HeaderValue::from_static(USER_AGENT));
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
        headers.insert("Connection", HeaderValue::from_static("close"));
        headers.insert(
            "X-Requested-With",
            HeaderValue::from_static("com.hypergryph.skland"),
        );
        headers.insert(
            "dId",
            HeaderValue::from_str(&self.d_id).context("invalid dId header")?,
        );
        Ok(headers)
    }

    fn sign_headers(&self, url: &str, method: &str, body: Option<&str>) -> Result<HeaderMap> {
        let mut headers = self.base_headers()?;
        let cred = self.cred.as_deref().context("missing cred")?;
        headers.insert(
            "cred",
            HeaderValue::from_str(cred).context("invalid cred header")?,
        );

        let parsed_url = Url::parse(url).context("invalid sign url")?;
        let payload = if method.eq_ignore_ascii_case("get") {
            parsed_url.query().unwrap_or_default().to_string()
        } else {
            body.unwrap_or_default().to_string()
        };
        let signature = self.generate_signature(parsed_url.path(), &payload)?;
        headers.insert(
            "sign",
            HeaderValue::from_str(&signature.sign).context("invalid sign header")?,
        );
        headers.insert("platform", HeaderValue::from_static("3"));
        headers.insert(
            "timestamp",
            HeaderValue::from_str(&signature.timestamp).context("invalid timestamp header")?,
        );
        headers.insert("vName", HeaderValue::from_static("1.0.0"));
        Ok(headers)
    }

    fn generate_signature(&self, path: &str, body_or_query: &str) -> Result<SignatureHeaders> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs()
            .saturating_sub(2)
            .to_string();

        let cred_token = self.cred_token.as_deref().context("missing cred token")?;
        let header_ca = format!(
            "{{\"platform\":\"3\",\"timestamp\":\"{}\",\"dId\":{},\"vName\":\"1.0.0\"}}",
            timestamp,
            serde_json::to_string(&self.d_id).context("failed to encode dId")?
        );
        let signing_string = format!("{path}{body_or_query}{timestamp}{header_ca}");

        let mut mac =
            HmacSha256::new_from_slice(cred_token.as_bytes()).context("invalid HMAC key")?;
        mac.update(signing_string.as_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        Ok(SignatureHeaders {
            sign: md5_hex(hmac_hex),
            timestamp,
        })
    }
}

fn render_plain_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
