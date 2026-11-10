import re
import socket
import time
import subprocess

import pytest

from conftest import (
    CLIENT,
    SERVER,
    collect,
    compute_hmac,
    compute_secret,
    free_port,
    make_packet,
    run_client,
)


def test_success_exchange(server_proc):
    proc, host, port = server_proc
    result = run_client(host, port, timeout=8)
    assert result.returncode == 0, result.stderr
    match = re.search(r"ok exchange=(\d+)", result.stdout)
    assert match, result.stdout
    exchange_id = match.group(1)

    time.sleep(0.2)
    out, err = collect(proc)
    assert f"ok exchange={exchange_id}" in out, (out, err)


def test_client_timeout():
    port = free_port()
    start = time.monotonic()
    result = run_client("127.0.0.1", port, timeout=8)
    elapsed = time.monotonic() - start
    assert result.returncode == 1
    assert "INIT_ACK timeout" in result.stderr
    assert 4.5 <= elapsed < 8


def test_bad_magic(server_proc):
    proc, host, port = server_proc
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    packet = bytearray(make_packet(1, 1, b"\x00" * 32))
    packet[0] ^= 0xFF
    sock.sendto(bytes(packet), (host, port))
    time.sleep(0.3)
    out, err = collect(proc)
    assert "wrong value at MAGIC" in err, (out, err)


def test_truncated_packet(server_proc):
    proc, host, port = server_proc
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"\x00" * 11, (host, port))
    time.sleep(0.3)
    out, err = collect(proc)
    assert "wrong value at LENGTH" in err, (out, err)


def test_bad_type(server_proc):
    proc, host, port = server_proc
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(make_packet(9, 1, b"\x00" * 32), (host, port))
    time.sleep(0.3)
    out, err = collect(proc)
    assert "wrong value at TYPE" in err, (out, err)


def test_wrong_sender_ignored(server_proc):
    proc, host, port = server_proc
    exchange_id = 777
    client_random = bytes(range(32))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.bind(("127.0.0.1", 0))
    sock.sendto(make_packet(1, exchange_id, client_random), (host, port))

    init_ack, _ = sock.recvfrom(256)
    assert len(init_ack) == 12 + 64
    server_random = init_ack[12:44]
    nonce = init_ack[44:76]
    secret = compute_secret(client_random, server_random, nonce, exchange_id)
    tag = compute_hmac(secret, 3, exchange_id, client_random, server_random, nonce)

    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attacker.sendto(make_packet(3, exchange_id, tag), (host, port))
    time.sleep(0.2)

    sock.sendto(make_packet(3, exchange_id, tag), (host, port))
    ack, _ = sock.recvfrom(256)
    assert len(ack) == 12 + 32
    assert ack[12:44] == compute_hmac(
        secret, 4, exchange_id, client_random, server_random, nonce
    )

    time.sleep(0.2)
    out, err = collect(proc)
    assert f"ok exchange={exchange_id}" in out, (out, err)
    assert "wrong value at SENDER" in err, (out, err)


def test_hmac_mismatch(server_proc):
    proc, host, port = server_proc
    exchange_id = 888
    client_random = bytes([5] * 32)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.bind(("127.0.0.1", 0))
    sock.sendto(make_packet(1, exchange_id, client_random), (host, port))

    init_ack, _ = sock.recvfrom(256)
    server_random = init_ack[12:44]
    nonce = init_ack[44:76]
    secret = compute_secret(client_random, server_random, nonce, exchange_id)
    tag = compute_hmac(secret, 3, exchange_id, client_random, server_random, nonce)
    wrong_tag = bytes(byte ^ 0xFF for byte in tag)

    sock.sendto(make_packet(3, exchange_id, wrong_tag), (host, port))
    time.sleep(0.3)
    sock.sendto(make_packet(3, exchange_id, tag), (host, port))
    ack, _ = sock.recvfrom(256)
    assert ack[12:44] == compute_hmac(
        secret, 4, exchange_id, client_random, server_random, nonce
    )

    time.sleep(0.2)
    out, err = collect(proc)
    assert "Invalid HMAC" in err, (out, err)
    assert f"ok exchange={exchange_id}" in out, (out, err)


def test_repeated_exchange_id(server_proc):
    proc, host, port = server_proc
    exchange_id = 555
    client_random = bytes([1] * 32)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.bind(("127.0.0.1", 0))
    sock.sendto(make_packet(1, exchange_id, client_random), (host, port))
    init_ack, _ = sock.recvfrom(256)
    server_random = init_ack[12:44]
    nonce = init_ack[44:76]
    secret = compute_secret(client_random, server_random, nonce, exchange_id)
    tag = compute_hmac(secret, 3, exchange_id, client_random, server_random, nonce)
    sock.sendto(make_packet(3, exchange_id, tag), (host, port))
    ack, _ = sock.recvfrom(256)
    assert len(ack) == 12 + 32

    sock.sendto(make_packet(1, exchange_id, client_random), (host, port))
    time.sleep(0.3)
    out, err = collect(proc)
    assert "Repeated exchange_id" in err, (out, err)


def test_server_bind_error():
    result = subprocess.run(
        [str(SERVER), "256.256.256.256", "0"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "Failed to bind" in result.stderr


def test_client_bad_args():
    result = subprocess.run([str(CLIENT)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 1


def test_server_timeout_waiting_confirm(server_proc):
    proc, host, port = server_proc
    exchange_id_a = 1001
    client_random_a = bytes([2] * 32)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.bind(("127.0.0.1", 0))
    sock.sendto(make_packet(1, exchange_id_a, client_random_a), (host, port))
    init_ack, _ = sock.recvfrom(256)
    assert len(init_ack) == 12 + 64

    # Do not send CONFIRM; let the server hit its 5s deadline.
    time.sleep(6)

    exchange_id_b = 1002
    client_random_b = bytes([3] * 32)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.settimeout(3)
    sock2.bind(("127.0.0.1", 0))
    sock2.sendto(make_packet(1, exchange_id_b, client_random_b), (host, port))
    init_ack2, _ = sock2.recvfrom(256)
    server_random_b = init_ack2[12:44]
    nonce_b = init_ack2[44:76]
    secret_b = compute_secret(client_random_b, server_random_b, nonce_b, exchange_id_b)
    tag_b = compute_hmac(secret_b, 3, exchange_id_b, client_random_b, server_random_b, nonce_b)
    sock2.sendto(make_packet(3, exchange_id_b, tag_b), (host, port))
    ack2, _ = sock2.recvfrom(256)
    assert ack2[12:44] == compute_hmac(
        secret_b, 4, exchange_id_b, client_random_b, server_random_b, nonce_b
    )

    time.sleep(0.2)
    out, err = collect(proc)
    assert f"ok exchange={exchange_id_b}" in out, (out, err)
    assert f"ok exchange={exchange_id_a}" not in out, (out, err)
