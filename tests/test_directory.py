"""Tests for the well-known directory fetch helper.

Covers: parse happy path, missing fields, malformed JSON, 404 handling,
key lookup, and hex validation.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from pipelock_verify._directory import (
    WELL_KNOWN_PATH,
    Directory,
    DirectoryFetchError,
    fetch_directory,
    parse_directory,
)

# ---- Parsing tests ----


def _valid_directory_json() -> dict:
    return {
        "keys": [
            {
                "keyid": "pipelock-mediation-prod",
                "alg": "ed25519",
                "public_key": "70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e",
                "use": "pipelock-mediation",
            },
        ],
    }


class TestParseDirectory:
    def test_valid_directory(self):
        d = parse_directory(_valid_directory_json())
        assert len(d.keys) == 1
        assert d.keys[0].keyid == "pipelock-mediation-prod"
        assert d.keys[0].algorithm == "ed25519"
        assert d.keys[0].use == "pipelock-mediation"
        assert len(bytes.fromhex(d.keys[0].public_key)) == 32

    def test_from_json_bytes(self):
        raw = json.dumps(_valid_directory_json()).encode()
        d = parse_directory(raw)
        assert len(d.keys) == 1

    def test_from_json_string(self):
        raw = json.dumps(_valid_directory_json())
        d = parse_directory(raw)
        assert len(d.keys) == 1

    def test_missing_keys_array(self):
        with pytest.raises(DirectoryFetchError, match="keys"):
            parse_directory({})

    def test_keys_not_array(self):
        with pytest.raises(DirectoryFetchError, match="keys"):
            parse_directory({"keys": "not-a-list"})

    def test_key_entry_not_object(self):
        with pytest.raises(DirectoryFetchError, match="keys\\[0\\]"):
            parse_directory({"keys": ["not-an-object"]})

    def test_missing_keyid(self):
        d = _valid_directory_json()
        del d["keys"][0]["keyid"]
        with pytest.raises(DirectoryFetchError, match="keyid"):
            parse_directory(d)

    def test_missing_alg(self):
        d = _valid_directory_json()
        del d["keys"][0]["alg"]
        with pytest.raises(DirectoryFetchError, match="alg"):
            parse_directory(d)

    def test_missing_public_key(self):
        d = _valid_directory_json()
        del d["keys"][0]["public_key"]
        with pytest.raises(DirectoryFetchError, match="public_key"):
            parse_directory(d)

    def test_missing_use(self):
        d = _valid_directory_json()
        del d["keys"][0]["use"]
        with pytest.raises(DirectoryFetchError, match="use"):
            parse_directory(d)

    def test_invalid_hex_key(self):
        d = _valid_directory_json()
        d["keys"][0]["public_key"] = "not-hex"
        with pytest.raises(DirectoryFetchError, match="hex"):
            parse_directory(d)

    def test_wrong_key_length(self):
        d = _valid_directory_json()
        d["keys"][0]["public_key"] = "00" * 16  # 16 bytes, not 32
        with pytest.raises(DirectoryFetchError, match="32 bytes"):
            parse_directory(d)

    def test_malformed_json(self):
        with pytest.raises(DirectoryFetchError, match="parsing directory"):
            parse_directory(b"not-json{")

    def test_not_an_object(self):
        with pytest.raises(DirectoryFetchError, match="must be a JSON object"):
            parse_directory(b"[]")

    def test_multiple_keys(self):
        d = _valid_directory_json()
        d["keys"].append(
            {
                "keyid": "backup-key",
                "alg": "ed25519",
                "public_key": "00" * 32,
                "use": "pipelock-mediation",
            }
        )
        result = parse_directory(d)
        assert len(result.keys) == 2
        assert result.keys[1].keyid == "backup-key"


# ---- Directory lookup methods ----


class TestDirectoryLookup:
    def test_get_key_found(self):
        d = parse_directory(_valid_directory_json())
        k = d.get_key("pipelock-mediation-prod")
        assert k is not None
        assert k.keyid == "pipelock-mediation-prod"

    def test_get_key_not_found(self):
        d = parse_directory(_valid_directory_json())
        assert d.get_key("nonexistent") is None

    def test_public_key_hex_by_keyid(self):
        d = parse_directory(_valid_directory_json())
        assert d.public_key_hex("pipelock-mediation-prod") is not None

    def test_public_key_hex_first_key(self):
        d = parse_directory(_valid_directory_json())
        assert d.public_key_hex() == d.keys[0].public_key

    def test_public_key_hex_empty_directory(self):
        d = Directory(keys=[])
        assert d.public_key_hex() is None

    def test_public_key_hex_missing_keyid(self):
        d = parse_directory(_valid_directory_json())
        assert d.public_key_hex("nonexistent") is None


# ---- HTTP fetch tests (local server) ----


class _DirectoryHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that serves the directory JSON or returns 404."""

    directory_json: bytes | None = None
    status_code: int = 200

    def do_GET(self):
        if self.path == WELL_KNOWN_PATH and self.directory_json is not None:
            self.send_response(self.status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(self.directory_json)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass  # Suppress HTTP server logs in test output.


def _start_test_server(directory_json: bytes | None = None, status_code: int = 200):
    """Start a local HTTP server returning the given directory JSON."""
    handler = type(
        "Handler",
        (_DirectoryHandler,),
        {"directory_json": directory_json, "status_code": status_code},
    )
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class TestFetchDirectory:
    def test_happy_path(self):
        body = json.dumps(_valid_directory_json()).encode()
        server = _start_test_server(body)
        try:
            host = f"127.0.0.1:{server.server_address[1]}"
            d = fetch_directory(host, scheme="http")
            assert len(d.keys) == 1
            assert d.keys[0].keyid == "pipelock-mediation-prod"
        finally:
            server.shutdown()

    def test_404_raises(self):
        server = _start_test_server(None)  # No directory JSON -> 404
        try:
            host = f"127.0.0.1:{server.server_address[1]}"
            with pytest.raises(DirectoryFetchError, match="fetching"):
                fetch_directory(host, scheme="http")
        finally:
            server.shutdown()

    def test_malformed_json_raises(self):
        server = _start_test_server(b"not-json{")
        try:
            host = f"127.0.0.1:{server.server_address[1]}"
            with pytest.raises(DirectoryFetchError, match="parsing directory"):
                fetch_directory(host, scheme="http")
        finally:
            server.shutdown()

    def test_unreachable_host(self):
        with pytest.raises(DirectoryFetchError, match="fetching"):
            fetch_directory("127.0.0.1:1", scheme="http", timeout=0.5)
