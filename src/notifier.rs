use anyhow::Result;
use reqwest::blocking::Client;

use crate::utils::{object_from_pairs, python_json_string};

pub fn send_webhook(http: &Client, url: &str, content: &str) -> Result<()> {
    if url.trim().is_empty() {
        return Ok(());
    }

    let payload = object_from_pairs([
        ("msgtype", serde_json::Value::String("text".to_string())),
        (
            "text",
            object_from_pairs([("content", serde_json::Value::String(content.to_string()))]),
        ),
        (
            "title",
            serde_json::Value::String("SKAS Report".to_string()),
        ),
        ("body", serde_json::Value::String(content.to_string())),
    ]);

    let body = if url.contains("dingtalk") || url.contains("feishu") {
        python_json_string(&payload)
    } else {
        python_json_string(&object_from_pairs([
            ("content", serde_json::Value::String(content.to_string())),
            ("message", serde_json::Value::String(content.to_string())),
        ]))
    };

    let _ = http
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;

    Ok(())
}
