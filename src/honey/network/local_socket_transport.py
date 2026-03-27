from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from collections.abc import Callable
from queue import Empty, Queue

from honey.support.telemetry import timed_metric

logger = logging.getLogger(__name__)


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def _recv_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    return _recv_exact(sock, size)


def start_local_socket_transport(
    pid: int,
    addresses: list[tuple[str, int]],
    inbound_messages: Queue,
    outbound_messages: Queue,
    stop_event: threading.Event,
    *,
    on_inbound_enqueued: Callable[[int], None] | None = None,
) -> tuple[threading.Thread, threading.Thread]:
    host, port = addresses[pid]
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(64)
    server_sock.settimeout(0.2)

    connections: dict[int, socket.socket] = {}
    conn_lock = threading.Lock()
    send_failures: dict[int, int] = {}

    def handle_conn(conn: socket.socket) -> None:
        with conn:
            while not stop_event.is_set():
                try:
                    with timed_metric("socket.recv.seconds", node=pid):
                        payload = _recv_frame(conn)
                    inbound_messages.put(payload)
                    if on_inbound_enqueued is not None:
                        on_inbound_enqueued(inbound_messages.qsize())
                except ConnectionError, OSError:
                    break
                except Exception:
                    logger.exception("Unexpected inbound socket error", extra={"node": pid})
                    break

    def server_loop() -> None:
        try:
            while not stop_event.is_set():
                try:
                    conn, _addr = server_sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if stop_event.is_set():
                        break
                    logger.exception("Server accept failed", extra={"node": pid})
                    time.sleep(0.01)
                    continue
                t = threading.Thread(target=handle_conn, args=(conn,), daemon=True)
                t.start()
        finally:
            try:
                server_sock.close()
            except OSError:
                pass

    def get_conn(recipient: int) -> socket.socket:
        with conn_lock:
            existing = connections.get(recipient)
            if existing is not None:
                return existing

        target = addresses[recipient]
        while not stop_event.is_set():
            sock_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_obj.settimeout(0.5)
            try:
                sock_obj.connect(target)
                sock_obj.settimeout(None)
                with conn_lock:
                    connections[recipient] = sock_obj
                return sock_obj
            except OSError:
                sock_obj.close()
                time.sleep(0.01)

        raise RuntimeError("transport stopped")

    def sender_loop() -> None:
        while not stop_event.is_set():
            try:
                recipient, payload = outbound_messages.get(timeout=0.1)
            except Empty:
                continue

            try:
                sock_obj = get_conn(recipient)
                with timed_metric("socket.send.seconds", node=pid):
                    _send_frame(sock_obj, payload)
                send_failures.pop(recipient, None)
            except (ConnectionError, OSError, RuntimeError) as exc:
                if stop_event.is_set():
                    break

                failures = send_failures.get(recipient, 0) + 1
                send_failures[recipient] = failures
                if failures == 1 or failures % 50 == 0:
                    logger.warning(
                        "Retrying outbound transport send",
                        extra={
                            "node": pid,
                            "recipient": recipient,
                            "attempt": failures,
                            "error": repr(exc),
                        },
                    )

                with conn_lock:
                    broken = connections.pop(recipient, None)
                if broken is not None:
                    try:
                        broken.close()
                    except OSError:
                        pass
                outbound_messages.put((recipient, payload))
                time.sleep(0.01)
        with conn_lock:
            for sock_obj in connections.values():
                try:
                    sock_obj.close()
                except OSError:
                    pass
            connections.clear()

    server_thread = threading.Thread(target=server_loop, daemon=True)
    sender_thread = threading.Thread(target=sender_loop, daemon=True)
    server_thread.start()
    sender_thread.start()
    return server_thread, sender_thread
