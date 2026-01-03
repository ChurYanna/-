import os
import socket
import threading
import time
import queue
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog

from common_protocol import (
    MSG_ACK,
    MSG_FILE,
    MSG_TEXT,
    recv_message,
    safe_filename,
    send_message,
    set_tcp_keepalive,
)


def get_local_ipv4_list():
    # 尽量简单地枚举本机 IPv4（不同环境下可能不全，但够课堂/演示使用）
    ip_set = set()
    ip_set.add("0.0.0.0")
    ip_set.add("127.0.0.1")

    try:
        hostname = socket.gethostname()
        _name, _aliases, addrs = socket.gethostbyname_ex(hostname)
        for a in addrs:
            if a and ":" not in a:
                ip_set.add(a)
    except Exception:
        pass

    try:
        # 这个方法常能拿到当前对外通信会用的本机地址
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.connect(("8.8.8.8", 80))
        ip = t.getsockname()[0]
        t.close()
        if ip and ":" not in ip:
            ip_set.add(ip)
    except Exception:
        pass

    ip_list = list(ip_set)
    # 让 0.0.0.0 排在最前，方便直接选“所有网卡监听”
    ip_list.sort(key=lambda x: (x != "0.0.0.0", x))
    return ip_list


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("工业网络 Socket 服务端(可视化)")

        self.server_sock = None
        self.accept_thread = None
        self.running = False

        self.ui_queue = queue.Queue()

        default_save_dir = os.path.join(os.path.dirname(__file__), "recv_files")

        # 顶部：监听配置
        top = tk.Frame(root)
        top.pack(fill="x", padx=8, pady=6)

        tk.Label(top, text="监听IP:").pack(side="left")
        self.host_var = tk.StringVar(value="0.0.0.0")
        host_values = get_local_ipv4_list()
        self.host_combo = ttk.Combobox(top, textvariable=self.host_var, values=host_values, width=14, state="readonly")
        self.host_combo.pack(side="left", padx=(2, 10))
        # 如果列表里没有默认值，就选第一项
        if host_values and self.host_var.get() not in host_values:
            self.host_var.set(host_values[0])

        tk.Label(top, text="端口:").pack(side="left")
        self.port_var = tk.StringVar(value="9000")
        tk.Entry(top, textvariable=self.port_var, width=8).pack(side="left", padx=(2, 10))

        self.btn_start = tk.Button(top, text="启动", width=10, command=self.start_server)
        self.btn_start.pack(side="left")

        self.btn_stop = tk.Button(top, text="停止", width=10, command=self.stop_server, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))

        # 保存目录
        dir_row = tk.Frame(root)
        dir_row.pack(fill="x", padx=8)

        tk.Label(dir_row, text="保存目录:").pack(side="left")
        self.save_dir_var = tk.StringVar(value=default_save_dir)
        tk.Entry(dir_row, textvariable=self.save_dir_var).pack(side="left", padx=(2, 6), fill="x", expand=True)
        tk.Button(dir_row, text="选择...", width=10, command=self.choose_dir).pack(side="left")

        # 中间：日志
        mid = tk.Frame(root)
        mid.pack(fill="both", expand=True, padx=8, pady=6)

        self.log = tk.Text(mid, height=20, state="disabled")
        self.log.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="未启动")
        tk.Label(root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8, pady=(0, 6))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self.pump_ui_queue)

    def append_log(self, s):
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_dir(self):
        path = filedialog.askdirectory(title="选择接收文件保存目录")
        if path:
            self.save_dir_var.set(path)

    def set_running_ui(self, running):
        if running:
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            self.status_var.set("运行中")
        else:
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self.status_var.set("未启动")

    def start_server(self):
        if self.server_sock is not None:
            return

        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        if host == "":
            host = "0.0.0.0"

        try:
            port = int(port_str)
        except Exception:
            self.append_log("[!] 端口不合法")
            return

        save_dir = self.save_dir_var.get().strip()
        if save_dir == "":
            self.append_log("[!] 保存目录为空")
            return

        try:
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)
        except Exception as e:
            self.append_log("[!] 创建保存目录失败: " + str(e))
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen(5)
        except Exception as e:
            self.append_log("[!] 启动失败: " + str(e))
            try:
                s.close()
            except Exception:
                pass
            return

        self.server_sock = s
        self.running = True
        self.accept_thread = threading.Thread(target=self.accept_loop, args=(save_dir,), daemon=True)
        self.accept_thread.start()

        self.append_log("[+] 服务端已启动: %s:%s" % (host, port))
        self.append_log("[+] 文件保存目录: %s" % save_dir)
        self.set_running_ui(True)

    def stop_server(self):
        self.running = False

        if self.server_sock is not None:
            try:
                self.server_sock.close()
            except Exception:
                pass

        self.server_sock = None
        self.append_log("[-] 服务端已停止")
        self.set_running_ui(False)

    def accept_loop(self, save_dir):
        # 后台线程：接受连接
        while self.running and self.server_sock is not None:
            try:
                conn, addr = self.server_sock.accept()
            except Exception:
                break

            t = threading.Thread(target=self.handle_client, args=(conn, addr, save_dir), daemon=True)
            t.start()

        self.ui_queue.put("__SERVER_STOPPED__")

    def handle_client(self, conn, addr, save_dir):
        set_tcp_keepalive(conn)
        self.ui_queue.put("[+] 客户端连接: %s:%s" % (addr[0], addr[1]))

        try:
            while True:
                msg = recv_message(conn)
                if msg is None:
                    self.ui_queue.put("[-] 客户端断开: %s:%s" % (addr[0], addr[1]))
                    break

                msg_type, name_bytes, data_bytes = msg

                if msg_type == MSG_TEXT:
                    text = data_bytes.decode("utf-8", errors="ignore")
                    self.ui_queue.put("[TEXT] %s:%s -> %s" % (addr[0], addr[1], text))
                    send_message(conn, MSG_ACK, b"", ("已收到TEXT: " + str(len(data_bytes)) + "字节").encode("utf-8"))

                elif msg_type == MSG_FILE:
                    try:
                        filename = name_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        filename = "file.bin"

                    filename = safe_filename(filename)
                    ts = time.strftime("%Y%m%d_%H%M%S")
                    out_name = ts + "_" + filename
                    out_path = os.path.join(save_dir, out_name)

                    with open(out_path, "wb") as f:
                        f.write(data_bytes)

                    self.ui_queue.put("[FILE] %s:%s -> %s (%d 字节)" % (addr[0], addr[1], out_name, len(data_bytes)))
                    send_message(conn, MSG_ACK, b"", ("已收到FILE: " + out_name).encode("utf-8"))

                else:
                    self.ui_queue.put("[?] 未知类型 %s 来自 %s:%s" % (msg_type, addr[0], addr[1]))
                    send_message(conn, MSG_ACK, b"", "已收到未知类型".encode("utf-8"))

        except Exception as e:
            self.ui_queue.put("[!] 客户端异常 %s:%s 错误: %s" % (addr[0], addr[1], e))

        try:
            conn.close()
        except Exception:
            pass

    def pump_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if item == "__SERVER_STOPPED__":
                    # 避免重复 stop 日志；仅把 UI 切回未启动
                    if self.server_sock is not None:
                        self.stop_server()
                    else:
                        self.set_running_ui(False)
                else:
                    self.append_log(item)
        except queue.Empty:
            pass

        self.root.after(100, self.pump_ui_queue)

    def on_close(self):
        try:
            self.stop_server()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
