// Copyright 2026 YuzakiKokuban
// SPDX-License-Identifier: GPL-3.0-or-later

mod client;
mod notifier;
mod security;
mod utils;

use std::env;
use std::process;

use client::SkylandClient;
use notifier::send_webhook;
use reqwest::blocking::Client as HttpClient;
use utils::mask_token;

fn main() {
    let tokens = env::var("SKYLAND_TOKEN")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if tokens.is_empty() {
        eprintln!("No tokens found in SKYLAND_TOKEN");
        process::exit(1);
    }

    let enable_games = env::var("ENABLE_GAMES")
        .unwrap_or_else(|_| "arknights,endfield".to_string())
        .split(',')
        .map(str::trim)
        .filter(|game| !game.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let webhook_url = env::var("WEBHOOK_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    let webhook_client = HttpClient::new();

    let mut all_logs = Vec::new();
    let mut global_success = true;

    for (index, token) in tokens.iter().enumerate() {
        println!("Processing Account {}: {}", index + 1, mask_token(token));

        match SkylandClient::new(token.clone()) {
            Ok(mut client) => {
                let (success, logs) = client.run_sign(&enable_games);
                if !success {
                    global_success = false;
                }

                for log in &logs {
                    println!("{log}");
                }
                all_logs.extend(logs);
            }
            Err(error) => {
                global_success = false;
                let log = format!("Init Error: {error}");
                println!("{log}");
                all_logs.push(log);
            }
        }
    }

    if let Some(url) = webhook_url.as_deref() {
        if !all_logs.is_empty() {
            let _ = send_webhook(&webhook_client, url, &all_logs.join("\n"));
        }
    }

    if !global_success {
        process::exit(1);
    }
}
