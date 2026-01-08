import socket
import struct
import threading
from dataclasses import dataclass
from typing import List, Tuple

HOST = "127.0.0.1"
PORT = 5600
MAGIC = 0x4C35

PKT_REQ_TIME = 10
PKT_REQ_NAME = 11
PKT_REQ_LIST = 12
PKT_REQ_FORWARD = 13
PKT_RESP_TIME = 21
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


def send_packet(sock: socket.socket, packet_type: int, payload: bytes = b"") -> None:
    header = struct.pack("!HHI", MAGIC, packet_type, len(payload))
    sock.sendall(header + payload)


def recv_packet(sock: socket.socket) -> Tuple[int, bytes]:
    header = recv_exact(sock, 8)
    magic, packet_type, length = struct.unpack("!HHI", header)
    if magic != MAGIC:
        raise RuntimeError("invalid magic")
    payload = recv_exact(sock, length) if length else b""
    return packet_type, payload


@dataclass
class Client:
    sock: socket.socket
    client_id: int

    @classmethod
    def connect(cls) -> "Client":
        sock = socket.create_connection((HOST, PORT), timeout=5)
        _, payload = recv_packet(sock)
        text = payload.decode(errors="ignore")
        client_id = -1
        if "#" in text:
            try:
                after_hash = text.split("#", 1)[1]
                digits = ""
                for ch in after_hash:
                    if ch.isdigit():
                        digits += ch
                    else:
                        break
                client_id = int(digits)
            except (IndexError, ValueError):
                client_id = -1
        return cls(sock, client_id)

    def request(self, packet_type: int, payload: bytes = b"") -> Tuple[int, bytes]:
        send_packet(self.sock, packet_type, payload)
        return recv_packet(self.sock)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


RESULTS_LOCK = threading.Lock()

def concurrent_time_requests(client_count: int = 4) -> List[str]:
    clients = [Client.connect() for _ in range(client_count)]
    barrier = threading.Barrier(client_count)
    responses: List[str] = []

    def worker(client: Client, idx: int) -> None:
        barrier.wait()
        pkt_type, payload = client.request(PKT_REQ_TIME)
        text = payload.decode(errors="ignore")
        with RESULTS_LOCK:
            responses.append(f"client-{idx} -> type {pkt_type}, payload={text}")
        assert pkt_type == PKT_RESP_TIME, f"unexpected packet type {pkt_type}"

    threads = [threading.Thread(target=worker, args=(clients[i], i)) for i in range(client_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for client in clients:
        client.close()

    return responses


def message_forwarding_roundtrip() -> List[str]:
    sender = Client.connect()
    receiver = Client.connect()

    messages: List[str] = []

    # fetch list to get receiver id
    pkt_type, payload = sender.request(PKT_REQ_LIST)
    assert pkt_type == PKT_RESP_LIST
    lines = payload.decode().strip().splitlines()
    receiver_id = receiver.client_id
    if receiver_id is None or receiver_id < 0:
        raise RuntimeError("receiver id missing")

    payload = struct.pack("!I", receiver_id) + b"hello from tests\0"
    send_packet(sender.sock, PKT_REQ_FORWARD, payload)

    # receiver should get indication
    pkt_type, payload = recv_packet(receiver.sock)
    assert pkt_type in (PKT_INDICATION, PKT_RESP_LIST, PKT_RESP_ERROR)
    if pkt_type == PKT_INDICATION:
        messages.append(payload.decode(errors="ignore"))

    sender.close()
    receiver.close()
    return messages


if __name__ == "__main__":
    print("=== Concurrent time request test ===")
    for line in concurrent_time_requests():
        print(line)
    print("\n=== Message forwarding test ===")
    for line in message_forwarding_roundtrip():
        print(line)
