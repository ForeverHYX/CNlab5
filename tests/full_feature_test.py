import socket
import struct
import threading
from typing import List, Optional, Tuple

HOST = "127.0.0.1"
PORT = 5600
MAGIC = 0x4C35

PKT_HELLO = 1
PKT_REQ_TIME = 10
PKT_REQ_NAME = 11
PKT_REQ_LIST = 12
PKT_REQ_FORWARD = 13
PKT_RESP_INFO = 20
PKT_RESP_TIME = 21
PKT_RESP_NAME = 22
PKT_RESP_LIST = 23
PKT_RESP_ERROR = 24
PKT_INDICATION = 30


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("connection closed early")
        data += chunk
    return data


def recv_packet(sock: socket.socket) -> Tuple[int, bytes]:
    header = recv_exact(sock, 8)
    magic, packet_type, payload_len = struct.unpack("!HHI", header)
    if magic != MAGIC:
        raise RuntimeError("invalid magic")
    payload = recv_exact(sock, payload_len) if payload_len else b""
    return packet_type, payload


def send_packet(sock: socket.socket, packet_type: int, payload: bytes = b"") -> None:
    header = struct.pack("!HHI", MAGIC, packet_type, len(payload))
    sock.sendall(header + payload)


class ProtoClient:
    def __init__(self, nickname: str):
        self.nickname = nickname
        self.sock: Optional[socket.socket] = None
        self.client_id: Optional[int] = None

    def connect(self) -> str:
        if self.sock is not None:
            raise RuntimeError("already connected")
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        pkt_type, payload = recv_packet(self.sock)
        assert pkt_type == PKT_HELLO
        hello = payload.decode(errors="ignore")
        self.client_id = self._extract_client_id(hello)
        return hello

    def disconnect(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.sock = None

    def request(self, packet_type: int, payload: bytes = b"") -> Tuple[int, bytes]:
        if self.sock is None:
            raise RuntimeError("not connected")
        send_packet(self.sock, packet_type, payload)
        return recv_packet(self.sock)

    def wait_for_packet(self) -> Tuple[int, bytes]:
        if self.sock is None:
            raise RuntimeError("not connected")
        return recv_packet(self.sock)

    @staticmethod
    def _extract_client_id(text: str) -> Optional[int]:
        if "#" not in text:
            return None
        part = text.split("#", 1)[1]
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        try:
            return int(digits)
        except ValueError:
            return None


def test_basic_menu_flow() -> List[str]:
    client = ProtoClient("basic")
    report: List[str] = []
    hello = client.connect()
    report.append(f"Connected: {hello}")

    pkt, payload = client.request(PKT_REQ_TIME)
    report.append(f"Time -> {pkt}: {payload.decode(errors='ignore')}")

    pkt, payload = client.request(PKT_REQ_NAME)
    report.append(f"Name -> {pkt}: {payload.decode(errors='ignore')}")

    pkt, payload = client.request(PKT_REQ_LIST)
    report.append(f"List -> {pkt}: {payload.decode(errors='ignore').strip()}")

    client.disconnect()
    report.append("Disconnected cleanly")
    return report


def test_message_exchange() -> List[str]:
    sender = ProtoClient("sender")
    receiver = ProtoClient("receiver")
    report: List[str] = []

    report.append(f"Sender HELLO: {sender.connect()}")
    report.append(f"Receiver HELLO: {receiver.connect()}")

    if receiver.client_id is None:
        raise RuntimeError("receiver client id unavailable")

    payload = struct.pack("!I", receiver.client_id) + b"lab05 automated message\0"
    pkt, data = sender.request(PKT_REQ_FORWARD, payload)
    report.append(f"Forward request ACK -> {pkt}: {data.decode(errors='ignore')}")

    pkt, data = receiver.wait_for_packet()
    if pkt != PKT_INDICATION:
        report.append(f"Unexpected packet type {pkt}")
    else:
        report.append(f"Receiver got message: {data.decode(errors='ignore')}")

    sender.disconnect()
    receiver.disconnect()
    report.append("Both clients disconnected")
    return report


def test_concurrent_time_requests(iterations: int = 5) -> List[str]:
    barrier = threading.Barrier(iterations)
    outputs: List[str] = []
    lock = threading.Lock()

    def worker(idx: int) -> None:
        client = ProtoClient(f"concurrent-{idx}")
        client.connect()
        barrier.wait()
        pkt, payload = client.request(PKT_REQ_TIME)
        with lock:
            outputs.append(f"thread-{idx} -> {pkt} {payload.decode(errors='ignore')}")
        client.disconnect()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(iterations)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return outputs


def main() -> None:
    print("=== Basic menu flow ===")
    for line in test_basic_menu_flow():
        print(line)

    print("\n=== Message exchange ===")
    for line in test_message_exchange():
        print(line)

    print("\n=== Concurrent time requests ===")
    for line in test_concurrent_time_requests():
        print(line)


if __name__ == "__main__":
    main()
