use serde_json::{Map, Value};

pub fn md5_hex(data: impl AsRef<[u8]>) -> String {
    format!("{:x}", md5::compute(data))
}

pub fn object_from_pairs<I, K>(pairs: I) -> Value
where
    I: IntoIterator<Item = (K, Value)>,
    K: Into<String>,
{
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

pub fn python_json_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => {
            let rendered = values
                .iter()
                .map(python_json_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{rendered}]")
        }
        Value::Object(map) => {
            let rendered = map
                .iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    format!("{key}: {}", python_json_string(value))
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{rendered}}}")
        }
    }
}

pub fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return format!("{token}***");
    }

    let prefix = &token[..4];
    let suffix = &token[token.len() - 4..];
    format!("{prefix}***{suffix}")
}
