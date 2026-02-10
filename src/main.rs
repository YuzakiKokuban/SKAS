mod security;
mod skyland;

use std::env;

fn main() {
    let tokens_env = env::var("SKYLAND_TOKENS").expect("SKYLAND_TOKENS must be set");
    let enable_arknights = env::var("ENABLE_ARKNIGHTS").unwrap_or("true".to_string()) == "true";
    let enable_endfield = env::var("ENABLE_ENDFIELD").unwrap_or("true".to_string()) == "true";

    let tokens: Vec<&str> = tokens_env
        .split(&[',', '\n'][..])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    println!("Found {} accounts", tokens.len());

    for (i, token) in tokens.iter().enumerate() {
        println!("Processing account {}", i + 1);
        match std::panic::catch_unwind(|| {
            process_account(token, enable_arknights, enable_endfield);
        }) {
            Ok(_) => println!("Account {} done", i + 1),
            Err(_) => println!("Account {} failed", i + 1),
        }
    }
}

fn process_account(token: &str, arknights: bool, endfield: bool) {
    let client = skyland::SkylandClient::new(token.to_string());
    let bindings = client.get_bindings();

    for binding in bindings {
        let app_code = binding["appCode"].as_str().unwrap_or("");
        let nick_name = binding["nickName"].as_str().unwrap_or("Unknown");

        match app_code {
            "arknights" => {
                if arknights {
                    println!("Signing Arknights for {}", nick_name);
                    client.sign_arknights(&binding);
                }
            }
            "endfield" => {
                if endfield {
                    println!("Signing Endfield for {}", nick_name);
                    client.sign_endfield(&binding);
                }
            }
            _ => {}
        }
    }
}
