import hashlib
import hmac
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SERVER = BUILD / "server"
CLIENT = BUILD / "client"

HEADER = struct.Struct("!IBBBBI")


def _readline_timeout(stream, timeout):
    result = {"line": None}

    def worker():
        try:
            result["line"] = stream.readline()
        except Exception:
            result["line"] = None

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    return result["line"]


@pytest.fixture(scope="session")
def built_binaries():
    missing = [str(path) for path in (SERVER, CLIENT) if not path.is_file()]
    if missing:
        pytest.fail(
            "Build first: cmake -S . -B build && cmake --build build. "
            "Missing: " + ", ".join(missing)
        )


@pytest.fixture
def server_proc(built_binaries):
    proc = subprocess.Popen(
        [str(SERVER), "127.0.0.1", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    line = _readline_timeout(proc.stdout, 5)
    assert line and line.startswith("listening 127.0.0.1:"), (
        f"server did not print listening line: {line!r}"
    )
    port = int(line.rsplit(":", 1)[1])
    yield proc, "127.0.0.1", port
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


def run_client(host, port, timeout=8):
    return subprocess.run(
        [str(CLIENT), host, str(port)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def make_packet(msg_type, exchange_id, payload=b""):
    return HEADER.pack(0x4B455931, 1, msg_type, 0, 0, exchange_id) + payload


def compute_secret(client_random, server_random, nonce, exchange_id):
    return hashlib.sha256(
        client_random + server_random + nonce + struct.pack("!I", exchange_id)
    ).digest()


def compute_hmac(secret, msg_type, exchange_id, client_random, server_random, nonce):
    message = (
        bytes([msg_type])
        + struct.pack("!I", exchange_id)
        + client_random
        + server_random
        + nonce
    )
    return hmac.new(secret, message, hashlib.sha256).digest()


def collect(proc, timeout=5):
    if proc.poll() is None:
        proc.terminate()
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return out, err
