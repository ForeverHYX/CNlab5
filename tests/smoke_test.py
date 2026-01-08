import socket
import struct

HOST = "127.0.0.1"
PORT = 5600
MAGIC = 0x4C35

PACKET_LABELS = {
    1: "HELLO",
    20: "RESP_INFO",
    21: "RESP_TIME",
    22: "RESP_NAME",
    23: "RESP_LIST",
    24: "RESP_ERROR",
}


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("connection closed early")
        data += chunk
    return data


def send_and_print(sock, pkt_type, payload=b""):
    header = struct.pack("!HHI", MAGIC, pkt_type, len(payload))
    sock.sendall(header + payload)
    resp_header = recv_exact(sock, 8)
    _, resp_type, resp_length = struct.unpack("!HHI", resp_header)
    resp_payload = recv_exact(sock, resp_length) if resp_length else b""
    print(f"RESP {PACKET_LABELS.get(resp_type, resp_type)}: {resp_payload.decode(errors='ignore')}")


def main():
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        hdr = recv_exact(sock, 8)
        magic, pkt_type, length = struct.unpack("!HHI", hdr)
        payload = recv_exact(sock, length)
        assert magic == MAGIC, "unexpected magic"
        print(f"HELLO packet: {payload.decode(errors='ignore')}")
        send_and_print(sock, 10)
        send_and_print(sock, 11)
        send_and_print(sock, 12)

if __name__ == "__main__":
    main()
