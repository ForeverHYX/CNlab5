#!/usr/bin/env python3
"""简单图形化客户端：使用 Tkinter + 原生 socket 与服务器通信。"""

import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

MAGIC = 0x4C35

PKT_REQ_TIME = 10
PKT_REQ_NAME = 11
PKT_REQ_LIST = 12
PKT_REQ_FORWARD = 13

PKT_HELLO = 1
PKT_RESP_INFO = 20
PKT_RESP_TIME = 21
PKT_RESP_NAME = 22
PKT_RESP_LIST = 23
PKT_RESP_ERROR = 24
PKT_INDICATION = 30

PACKET_TAGS = {
    PKT_HELLO: "[HELLO]",
    PKT_RESP_INFO: "[INFO]",
    PKT_RESP_TIME: "[TIME]",
    PKT_RESP_NAME: "[NAME]",
    PKT_RESP_LIST: "[CLIENTS]",
    PKT_RESP_ERROR: "[ERROR]",
    PKT_INDICATION: "[MESSAGE]",
}


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed by server")
        data += chunk
    return data


def recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 8)
    magic, pkt_type, payload_len = struct.unpack("!HHI", header)
    if magic != MAGIC:
        raise ConnectionError("invalid packet magic")
    payload = recv_exact(sock, payload_len) if payload_len else b""
    return pkt_type, payload


def send_packet(sock: socket.socket, pkt_type: int, payload: bytes = b"") -> None:
    header = struct.pack("!HHI", MAGIC, pkt_type, len(payload))
    sock.sendall(header + payload)


FORWARD_STRUCT = struct.Struct("!I I H H")


def decode_forward_payload(payload: bytes) -> str:
    if len(payload) < FORWARD_STRUCT.size:
        return "(指示负载格式错误)"
    sender_id, sender_ipv4, sender_port, _ = FORWARD_STRUCT.unpack_from(payload)
    message_bytes = payload[FORWARD_STRUCT.size:]
    if b"\0" in message_bytes:
        message_bytes = message_bytes.split(b"\0", 1)[0]
    text = message_bytes.decode(errors="ignore")
    sender_ip = socket.inet_ntoa(struct.pack("!I", sender_ipv4))
    sender_port = sender_port
    return f"From Client #{sender_id} ({sender_ip}:{sender_port})\n{text}"


class GuiClient:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Lab05 GUI 客户端")
        self.sock: socket.socket | None = None
        self.receiver_thread: threading.Thread | None = None
        self.receiver_running = threading.Event()
        self.msg_queue: queue.Queue[tuple[int, str]] = queue.Queue()

        self._build_widgets()
        self.root.after(100, self._drain_queue)

    def _build_widgets(self) -> None:
        frm_conn = tk.LabelFrame(self.root, text="服务器信息", padx=8, pady=8)
        frm_conn.pack(fill="x", padx=10, pady=5)

        tk.Label(frm_conn, text="地址").grid(row=0, column=0, sticky="w")
        self.entry_host = tk.Entry(frm_conn)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(frm_conn, text="端口").grid(row=0, column=2, sticky="w")
        self.entry_port = tk.Entry(frm_conn, width=6)
        self.entry_port.insert(0, "5600")
        self.entry_port.grid(row=0, column=3, padx=5, pady=2)

        self.btn_connect = tk.Button(frm_conn, text="连接", command=self.connect)
        self.btn_connect.grid(row=0, column=4, padx=5)
        self.btn_disconnect = tk.Button(frm_conn, text="断开", command=self.disconnect, state=tk.DISABLED)
        self.btn_disconnect.grid(row=0, column=5, padx=5)

        frm_actions = tk.LabelFrame(self.root, text="操作", padx=8, pady=8)
        frm_actions.pack(fill="x", padx=10, pady=5)

        self.btn_time = tk.Button(frm_actions, text="获取时间", width=12, command=lambda: self.simple_request(PKT_REQ_TIME), state=tk.DISABLED)
        self.btn_time.grid(row=0, column=0, padx=4, pady=2)
        self.btn_name = tk.Button(frm_actions, text="获取主机名", width=12, command=lambda: self.simple_request(PKT_REQ_NAME), state=tk.DISABLED)
        self.btn_name.grid(row=0, column=1, padx=4, pady=2)
        self.btn_list = tk.Button(frm_actions, text="获取客户端列表", width=14, command=lambda: self.simple_request(PKT_REQ_LIST), state=tk.DISABLED)
        self.btn_list.grid(row=0, column=2, padx=4, pady=2)

        tk.Label(frm_actions, text="目标编号").grid(row=1, column=0, sticky="e", pady=4)
        self.entry_target = tk.Entry(frm_actions, width=8)
        self.entry_target.grid(row=1, column=1, sticky="w")
        tk.Label(frm_actions, text="消息内容").grid(row=1, column=2, sticky="e")
        self.entry_message = tk.Entry(frm_actions, width=30)
        self.entry_message.grid(row=1, column=3, padx=4, pady=2)

        self.btn_send = tk.Button(frm_actions, text="发送消息", width=12, command=self.send_message, state=tk.DISABLED)
        self.btn_send.grid(row=1, column=4, padx=4)

        frm_log = tk.LabelFrame(self.root, text="消息日志", padx=8, pady=8)
        frm_log.pack(fill="both", expand=True, padx=10, pady=5)

        self.txt_log = scrolledtext.ScrolledText(frm_log, wrap=tk.WORD, height=18)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.insert(tk.END, "请先连接服务器...\n")
        self.txt_log.configure(state=tk.DISABLED)

    # --- Connection management -------------------------------------------------

    def connect(self) -> None:
        host = self.entry_host.get().strip()
        port_text = self.entry_port.get().strip()
        if not host or not port_text:
            messagebox.showwarning("提示", "请输入服务器地址和端口")
            return
        try:
            port = int(port_text)
        except ValueError:
            messagebox.showerror("错误", "端口必须是整数")
            return
        try:
            self.sock = socket.create_connection((host, port), timeout=5)
            self.sock.settimeout(None)  # revert to blocking mode to avoid idle timeouts
        except OSError as exc:
            messagebox.showerror("连接失败", str(exc))
            return

        self.receiver_running.set()
        self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.receiver_thread.start()
        self._set_connected(True)

    def disconnect(self) -> None:
        self.receiver_running.clear()
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None
        self._set_connected(False)

    def _set_connected(self, connected: bool) -> None:
        state = tk.NORMAL if connected else tk.DISABLED
        self.btn_disconnect.configure(state=tk.NORMAL if connected else tk.DISABLED)
        self.btn_connect.configure(state=tk.DISABLED if connected else tk.NORMAL)
        self.btn_time.configure(state=state)
        self.btn_name.configure(state=state)
        self.btn_list.configure(state=state)
        self.btn_send.configure(state=state)

    # --- Networking helpers ----------------------------------------------------

    def _receiver_loop(self) -> None:
        assert self.sock is not None
        try:
            while self.receiver_running.is_set():
                pkt_type, payload = recv_packet(self.sock)
                if pkt_type == PKT_INDICATION:
                    text = decode_forward_payload(payload)
                else:
                    text = payload.decode(errors="ignore")
                tag = PACKET_TAGS.get(pkt_type, f"[TYPE {pkt_type}]")
                self.msg_queue.put((pkt_type, f"{tag} {text}"))
        except (ConnectionError, OSError) as exc:
            self.msg_queue.put((PKT_RESP_ERROR, f"[ERROR] {exc}"))
        finally:
            self.receiver_running.clear()
            self.sock = None
            self._set_connected(False)

    def _drain_queue(self) -> None:
        try:
            while True:
                _, message = self.msg_queue.get_nowait()
                self._append_log(message)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _append_log(self, text: str) -> None:
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.insert(tk.END, text + "\n")
        self.txt_log.see(tk.END)
        self.txt_log.configure(state=tk.DISABLED)

    # --- Actions ---------------------------------------------------------------

    def simple_request(self, pkt_type: int) -> None:
        if not self.sock:
            messagebox.showwarning("提示", "尚未连接")
            return
        try:
            send_packet(self.sock, pkt_type)
        except OSError as exc:
            messagebox.showerror("发送失败", str(exc))

    def send_message(self) -> None:
        if not self.sock:
            messagebox.showwarning("提示", "尚未连接")
            return
        target_text = self.entry_target.get().strip()
        message = self.entry_message.get().strip()
        if not target_text or not message:
            messagebox.showwarning("提示", "请填写目标编号和消息内容")
            return
        try:
            target_id = int(target_text)
        except ValueError:
            messagebox.showerror("错误", "目标编号应为整数")
            return
        payload = struct.pack("!I", target_id) + message.encode() + b"\0"
        try:
            send_packet(self.sock, PKT_REQ_FORWARD, payload)
        except OSError as exc:
            messagebox.showerror("发送失败", str(exc))


def main() -> None:
    root = tk.Tk()
    app = GuiClient(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.disconnect(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
