#!/usr/bin/env python3
"""Loopback audit harness for Codex app-server auth-status exposure.

This script intentionally requests `getAuthStatus` with `includeToken:false`.
It verifies that the local app-server auth method is reachable without
extracting or persisting live bearer tokens.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading websocket frame")
        data.extend(chunk)
    return bytes(data)


def websocket_text_frame(payload: str) -> bytes:
    data = payload.encode("utf-8")
    mask = secrets.token_bytes(4)
    if len(data) < 126:
        header = bytes([0x81, 0x80 | len(data)])
    elif len(data) <= 0xFFFF:
        header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", len(data))
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", len(data))
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
    return header + mask + masked


def read_websocket_text(sock: socket.socket) -> str:
    first = recv_exact(sock, 2)
    opcode = first[0] & 0x0F
    masked = (first[1] & 0x80) != 0
    length = first[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    if opcode == 0x8:
        raise RuntimeError("server closed websocket connection")
    if opcode != 0x1:
        raise RuntimeError(f"unexpected websocket opcode: {opcode}")
    return payload.decode("utf-8")


def connect_websocket(host: str, port: int) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=5)
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(sock.recv(4096))
    header_blob = bytes(response).split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    status_line = header_blob.splitlines()[0]
    if " 101 " not in f" {status_line} ":
        raise RuntimeError(f"websocket upgrade failed: {status_line}")
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")
    if f"Sec-WebSocket-Accept: {expected}".lower() not in header_blob.lower():
        raise RuntimeError("websocket upgrade returned unexpected accept key")
    sock.settimeout(30)
    return sock


def wait_readyz(host: str, port: int, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    url = f"http://{host}:{port}/readyz"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {url}")


def rpc(sock: socket.socket, payload: dict) -> dict:
    sock.sendall(websocket_text_frame(json.dumps(payload, separators=(",", ":"))))
    while True:
        message = json.loads(read_websocket_text(sock))
        if message.get("id") == payload.get("id"):
            return message


def build_report(
    auth_response: dict,
    bind_host: str,
    port: int,
    codex_binary: str,
    includeToken: bool,
    refresh_token: bool,
) -> dict:
    result = auth_response.get("result", {})
    return {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
        "codex_binary": codex_binary,
        "listener": f"ws://{bind_host}:{port}",
        "auth_method": result.get("authMethod"),
        "requires_openai_auth": result.get("requiresOpenaiAuth"),
        "auth_token_returned": result.get("authToken") is not None,
        "refresh_token_requested": refresh_token,
        "note": "Audit-only probe. getAuthStatus was called with includeToken=false.",
    }


def auth_handoff(auth_response: dict) -> dict:
    result = auth_response.get("result", {})
    return {
        "auth_method": result.get("authMethod"),
        "access_token": result.get("authToken"),
        "requires_openai_auth": result.get("requiresOpenaiAuth"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit local Codex app-server auth-status reachability.")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4500)
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument(
        "--includeToken",
        action="store_true",
        help="Ask codex to return the auth token in the status metadata.",
    )
    parser.add_argument(
        "--refresh-token",
        action="store_true",
        help="Ask Codex to refresh auth state before returning non-secret status metadata.",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [args.codex_binary, "app-server", "--listen", f"ws://{args.host}:{args.port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_readyz(args.host, args.port, timeout_seconds=10)
        sock = connect_websocket(args.host, args.port)
        try:
            init = rpc(
                sock,
                {
                    "method": "initialize",
                    "id": 1,
                    "params": {
                        "clientInfo": {
                            "name": "codex-pickpocket-audit",
                            "title": "codex-pickpocket-audit",
                            "version": "0.1.0",
                        },
                        "capabilities": None,
                    },
                },
            )
            if "result" not in init:
                raise RuntimeError(f"initialize failed: {init}")
            auth = rpc(
                sock,
                {
                    "method": "getAuthStatus",
                    "id": 2,
                    "params": {
                        "includeToken": args.includeToken,
                        "refreshToken": args.refresh_token,
                    },
                },
            )
        finally:
            sock.close()
        if "result" not in auth:
            raise RuntimeError(f"getAuthStatus failed: {auth}")
        report = build_report(
            auth,
            args.host,
            args.port,
            args.codex_binary,
            args.includeToken,
            args.refresh_token,
        )
        stamp = report["timestamp_utc"].replace(":", "").replace("-", "")
        report_path = output_dir / f"{report['username']}-{stamp}.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(auth_handoff(auth), ensure_ascii=False, separators=(",", ":")))
        print(json.dumps({"report": str(report_path), "auth_method": report["auth_method"]}), file=sys.stderr)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
