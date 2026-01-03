import os
import socket
import threading
import queue
import tkinter as tk
from tkinter import filedialog

from common_protocol import MSG_FILE, MSG_TEXT, recv_message, send_message, set_tcp_keepalive


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("工业网络 Socket 客户端(可视化)")

        self.sock = None
        self.recv_thread = None
        self.running = False
        self.ui_queue = queue.Queue()

        # 顶部：连接信息
        top = tk.Frame(root)
        top.pack(fill="x", padx=8, pady=6)

        tk.Label(top, text="IP:").pack(side="left")
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(top, textvariable=self.host_var, width=16).pack(side="left", padx=(2, 10))

        tk.Label(top, text="端口:").pack(side="left")
        self.port_var = tk.StringVar(value="9000")
        tk.Entry(top, textvariable=self.port_var, width=8).pack(side="left", padx=(2, 10))

        self.btn_connect = tk.Button(top, text="连接", width=10, command=self.connect)
        self.btn_connect.pack(side="left")

        self.btn_disconnect = tk.Button(top, text="断开", width=10, command=self.disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(6, 0))

        # 中间：日志
        mid = tk.Frame(root)
        mid.pack(fill="both", expand=True, padx=8)

        self.log = tk.Text(mid, height=18, state="disabled")
        self.log.pack(fill="both", expand=True)

        # 底部：发送区
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=8, pady=6)

        tk.Label(bottom, text="文本:").pack(side="left")
        self.text_var = tk.StringVar()
        tk.Entry(bottom, textvariable=self.text_var, width=40).pack(side="left", padx=(2, 6), fill="x", expand=True)

        self.btn_send_text = tk.Button(bottom, text="发送文本", width=10, command=self.send_text, state="disabled")
        self.btn_send_text.pack(side="left", padx=(0, 6))

        self.btn_send_file = tk.Button(bottom, text="发送文件", width=10, command=self.send_file, state="disabled")
        self.btn_send_file.pack(side="left")

        self.status_var = tk.StringVar(value="未连接")
        tk.Label(root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8, pady=(0, 6))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self.pump_ui_queue)

    def append_log(self, s):
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_connected_ui(self, connected):
        if connected:
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
            self.btn_send_text.configure(state="normal")
            self.btn_send_file.configure(state="normal")
            self.status_var.set("已连接")
        else:
            self.btn_connect.configure(state="normal")
            self.btn_disconnect.configure(state="disabled")
            self.btn_send_text.configure(state="disabled")
            self.btn_send_file.configure(state="disabled")
            self.status_var.set("未连接")

    def connect(self):
        if self.sock is not None:
            return

        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        if host == "":
            host = "127.0.0.1"

        try:
            port = int(port_str)
        except Exception:
            self.append_log("[!] 端口不合法")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_tcp_keepalive(s)
            s.connect((host, port))
        except Exception as e:
            self.append_log("[!] 连接失败: " + str(e))
            try:
                s.close()
            except Exception:
                pass
            return

        self.sock = s
        self.running = True
        self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
        self.recv_thread.start()

        self.append_log("[+] 已连接到 %s:%s" % (host, port))
        self.set_connected_ui(True)

    def disconnect(self):
        self.running = False
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.append_log("[-] 已断开")
        self.set_connected_ui(False)

    def recv_loop(self):
        # 后台线程：收服务端 ACK/消息
        while self.running and self.sock is not None:
            try:
                msg = recv_message(self.sock)
                if msg is None:
                    self.ui_queue.put("[-] 服务端已断开")
                    break

                msg_type, _name, data = msg
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = str(data)

                self.ui_queue.put("[服务端] type=%s %s" % (msg_type, text))
            except Exception as e:
                self.ui_queue.put("[!] 接收异常: " + str(e))
                break

        # 收线程退出时，自动切回未连接状态
        self.ui_queue.put("__DISCONNECTED__")

    def pump_ui_queue(self):
        # 主线程：把后台线程消息刷到界面
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if item == "__DISCONNECTED__":
                    # 避免重复断开日志
                    if self.sock is not None:
                        self.disconnect()
                    else:
                        self.set_connected_ui(False)
                else:
                    self.append_log(item)
        except queue.Empty:
            pass

        self.root.after(100, self.pump_ui_queue)

    def send_text(self):
        if self.sock is None:
            return
        text = self.text_var.get()
        if text.strip() == "":
            return

        try:
            send_message(self.sock, MSG_TEXT, b"", text.encode("utf-8"))
            self.append_log("[我] " + text)
            self.text_var.set("")
        except Exception as e:
            self.append_log("[!] 发送失败: " + str(e))

    def send_file(self):
        if self.sock is None:
            return

        path = filedialog.askopenfilename(title="选择要发送的文件")
        if not path:
            return

        try:
            name = os.path.basename(path)
            with open(path, "rb") as f:
                data = f.read()
            send_message(self.sock, MSG_FILE, name.encode("utf-8"), data)
            self.append_log("[我] 已发送文件: %s (%d 字节)" % (name, len(data)))
        except Exception as e:
            self.append_log("[!] 发送文件失败: " + str(e))

    def on_close(self):
        try:
            self.disconnect()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
