# Copyright 2026 YuzakiKokuban
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import os
import subprocess
import sys
import tempfile
from getpass import getpass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = ROOT / "skyland-token.enc"
KEY_NAME = "SKYLAND_TOKEN_KEY"
TOKEN_NAME = "SKYLAND_TOKEN"
ACCOUNT_URL = "https://web-api.skland.com/account/info/hg"


def token_list(tokens):
    if not tokens or any(
        not token or any(c.isspace() or c in ",\x00" for c in token)
        for token in tokens
    ):
        raise ValueError("Invalid Skyland token list.")
    return ",".join(tokens)


def encode_tokens(cipher, tokens):
    return cipher.encrypt(token_list(tokens).encode("utf-8"))


def decode_tokens(cipher, ciphertext):
    return token_list(cipher.decrypt(ciphertext.strip()).decode("utf-8").split(","))


def export_tokens(account_count, browser_channel):
    from playwright.sync_api import sync_playwright

    tokens = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False, channel=browser_channel)
        try:
            for index in range(account_count):
                context = browser.new_context()
                try:
                    context.new_page().goto("https://www.skland.com", wait_until="domcontentloaded")
                    input(f"Log in to Skyland for account {index + 1}, then press Enter here: ")
                    response = context.request.get(ACCOUNT_URL, max_redirects=0)
                    payload = response.json() if response.ok else {}
                    data = payload.get("data") if isinstance(payload, dict) else None
                    token = data.get("content") if isinstance(data, dict) else None
                    if not isinstance(token, str) or payload.get("code") != 0:
                        raise RuntimeError(f"Could not export account {index + 1}. Log in and retry.")
                    tokens.append(token)
                finally:
                    context.close()
        finally:
            browser.close()
    return tokens


def save_tokens(cipher, tokens):
    ciphertext = encode_tokens(cipher, tokens)
    temp = tempfile.NamedTemporaryFile(dir=ROOT, delete=False)
    path = Path(temp.name)
    try:
        with temp:
            temp.write(ciphertext + b"\n")
        path.replace(TOKEN_FILE)
    finally:
        path.unlink(missing_ok=True)


def cargo_run(env, *args):
    return subprocess.run(
        ["cargo", "run", "--release", "--locked", "--", *args],
        cwd=ROOT,
        env=env,
        check=False,
    ).returncode


def main():
    parser = argparse.ArgumentParser(description="Manage encrypted Skyland tokens.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generate-key")
    export = commands.add_parser("export")
    export.add_argument("--accounts", type=int, default=1)
    export.add_argument(
        "--browser",
        choices=("chromium", "msedge", "chrome"),
        default="msedge" if os.name == "nt" else "chromium",
    )
    commands.add_parser("run")
    args = parser.parse_args()

    if args.command == "generate-key":
        print(Fernet.generate_key().decode("ascii"))
        return 0

    key = os.environ.pop(KEY_NAME, "")
    if args.command == "run":
        if TOKEN_FILE.exists():
            if not key:
                raise RuntimeError(f"{KEY_NAME} is required for the encrypted token file.")
            try:
                os.environ[TOKEN_NAME] = decode_tokens(Fernet(key), TOKEN_FILE.read_bytes())
            except (InvalidToken, ValueError):
                raise RuntimeError("Cannot decrypt the token file. Check the key and file.") from None
        return cargo_run(os.environ)

    if args.accounts < 1:
        parser.error("--accounts must be at least 1")
    if not key:
        key = getpass(f"{KEY_NAME}: ").strip()
    try:
        cipher = Fernet(key)
    except ValueError:
        raise RuntimeError("Invalid encryption key. Use generate-key to create one.") from None
    tokens = export_tokens(args.accounts, args.browser)
    env = os.environ.copy()
    env[TOKEN_NAME] = token_list(tokens)
    if cargo_run(env, "--validate-token") != 0:
        raise RuntimeError("Token validation failed. The encrypted file was not replaced.")
    save_tokens(cipher, tokens)
    print(f"Saved {len(tokens)} account(s) to {TOKEN_FILE.name}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (EOFError, KeyboardInterrupt):
        sys.exit("Cancelled.")
    except RuntimeError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Token operation failed. Check browser installation, network, and file access.")
