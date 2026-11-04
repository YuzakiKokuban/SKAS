# Copyright 2026 YuzakiKokuban
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken

from scripts import skyland_token as helper
from scripts.skyland_token import decode_tokens, encode_tokens


class TokenFileTest(unittest.TestCase):
    def test_round_trip(self):
        cipher = Fernet(Fernet.generate_key())
        ciphertext = encode_tokens(cipher, ["fake-first", "fake-second"])
        self.assertNotIn(b"fake-first", ciphertext)
        self.assertEqual(decode_tokens(cipher, ciphertext), "fake-first,fake-second")

    def test_rejects_wrong_key_and_corruption(self):
        cipher = Fernet(Fernet.generate_key())
        ciphertext = encode_tokens(cipher, ["fake-token"])
        with self.assertRaises(InvalidToken):
            decode_tokens(Fernet(Fernet.generate_key()), ciphertext)
        with self.assertRaises(InvalidToken):
            decode_tokens(cipher, ciphertext[:20])

    def test_rejects_ambiguous_token(self):
        cipher = Fernet(Fernet.generate_key())
        with self.assertRaises(ValueError):
            encode_tokens(cipher, ["fake,token"])

    def test_run_uses_encrypted_file_or_legacy_secret(self):
        key = Fernet.generate_key().decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_file = root / "skyland-token.enc"
            with (
                patch.object(helper, "ROOT", root),
                patch.object(helper, "TOKEN_FILE", token_file),
                patch("sys.argv", ["skyland_token.py", "run"]),
                patch.dict(os.environ, {helper.KEY_NAME: key, helper.TOKEN_NAME: "legacy"}),
                patch.object(helper, "cargo_run", side_effect=lambda env: env[helper.TOKEN_NAME]),
            ):
                self.assertEqual(helper.main(), "legacy")
                helper.save_tokens(Fernet(key), ["encrypted"])
                os.environ[helper.KEY_NAME] = key
                self.assertEqual(helper.main(), "encrypted")
                self.assertNotIn(helper.KEY_NAME, os.environ)

                os.environ[helper.KEY_NAME] = Fernet.generate_key().decode("ascii")
                with self.assertRaisesRegex(RuntimeError, "Cannot decrypt"):
                    helper.main()
