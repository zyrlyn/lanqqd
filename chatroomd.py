# -*- coding: utf-8 -*-
"""
lanqqd 聊天室服务器 (QQ1999 群/聊天室协议)

协议逆向自 oicq.asm —— 一个 IRC 魔改的文本协议 (TCP, 行以 \\n 结尾):

  客户端连接后发登录包:  /! <v1> <v2> OICQ_<v1>/<v3> <昵称> 0
    (sub_406639: sprintf("/! %ld %d OICQ_%ld/%d %s %d", ...))
  服务器回:              OK        (登录成功)
                        EX        (昵称已被使用)
                        IN        (昵称非法)

  登录成功后:
    客户端发普通消息 = 纯文本行 + "\\n" (sub_406F63 发送, sub_406D96 接收)
    客户端命令:
      /b              房间列表        (sub_4072B0)
      /n <新昵称>     改名            (sub_40578E)
      /m OICQ_<号> <内容>  私聊      (sub_40578E)
      /i OICQ_<号>    邀请进入
      /t <新标题>     修改房间标题
      /j <房间>       加入房间
      /f +l / -l      锁定/解锁房间
      /f +s / -s      秘密/公开房间

  服务器 → 客户端:
    文本行直接显示; 支持 ANSI 颜色码 \\x1b[1m..\\x1b[6m
    (客户端 sub_406FAD 将其转为控制符 \\x01..\\x06 着色)
    以 '/' 开头的行走命令分发 (sub_406D96): 第2字符 ASCII 作命令码,
      /r -> 0x19, /t -> 0x18, 其余直接取字符值; 命令码 0x15 = 断开连接。

用法:
  python chatroomd.py [port]     # 默认 8001, 可同时监听 8002
"""
import socket
import sys
import threading
import time

HOST = "0.0.0.0"
DEFAULT_PORT = 8001
EXTRA_PORTS = [8002]

# 默认房间列表 (客户端 /b 或开房时下发)
DEFAULT_ROOMS = ["闲聊天地", "水晶之恋", "e网情深", "缘聚OICQ", "公测专区"]

# 客户端转义符颜色 (仅作参考; 服务器发 \\x1b[Nm 即可)
ESC = "\x1b"
COLOR = {1: "\x01", 2: "\x02", 3: "\x03", 4: "\x04", 5: "\x05", 6: "\x06"}


def color(text, n):
    """给文本包一层聊天室颜色码: ESC[n m 文本 (客户端转成控制符着色)"""
    return f"{ESC}[{n}m{text}"


class Client:
    """单个聊天室连接"""

    def __init__(self, conn, addr, server):
        self.conn = conn
        self.addr = addr
        self.server = server
        self.nick = None        # 登录后昵称
        self.buf = b""
        self.logged_in = False

    def send(self, text):
        """发送一条消息 (以 NUL 0x00 结尾)。

        客户端 sub_406D96 (OnReceive) 逐字节 recv(1), 只有读到 NUL(0x00)
        才把累积缓冲整体提交处理 (nReceived=1 != strlen=0);
        普通字节 (strlen=1) 会直接丢弃不提交。因此服务器发给客户端的
        每条消息必须以 "\\x00" 结尾, 而不是 "\\n"。
        """
        try:
            self.conn.sendall((text + "\x00").encode("gbk", errors="replace"))
        except OSError:
            pass

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass


class ChatRoomServer:
    """多房间聊天室服务器 (简化: 单房间)"""

    def __init__(self, port):
        self.port = port
        self.clients = {}       # id(client) -> Client
        self.lock = threading.Lock()

    def broadcast(self, text, exclude=None):
        """广播给所有客户端 (可排除一人)"""
        with self.lock:
            targets = list(self.clients.values())
        for c in targets:
            if c is not exclude and c.logged_in:
                c.send(text)

    def handle(self, conn, addr):
        c = Client(conn, addr, self)
        with self.lock:
            self.clients[id(c)] = c
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                c.buf += data
                while b"\n" in c.buf:
                    line, _, c.buf = c.buf.partition(b"\n")
                    self.handle_line(c, line)
        except (OSError, ConnectionResetError):
            pass
        finally:
            self.on_disconnect(c)
            c.close()
            with self.lock:
                self.clients.pop(id(c), None)

    def handle_line(self, c, raw):
        """处理一行客户端数据"""
        line = raw.decode("gbk", errors="replace").rstrip("\r")
        if not line:
            return
        print(f"[聊天室:{self.port}] {c.addr[0]}:{c.addr[1]} << {line!r}")

        # 未登录: 只接受 /! 登录包
        if not c.logged_in:
            self.do_login(c, line)
            return

        # 已登录: 以 / 开头是命令, 否则是普通聊天
        if line.startswith("/"):
            self.do_command(c, line)
        else:
            self.do_chat(c, line)

    # ── 登录 ──────────────────────────────────────────
    def do_login(self, c, line):
        if not line.startswith("/!"):
            c.send("IN")   # 非法登录包
            return
        parts = line.split(" ")
        # "/! v1 v2 OICQ_v1/v3 昵称 0"
        if len(parts) >= 5:
            nick = parts[4]
        else:
            nick = parts[-1] if parts else ""
        nick = nick.strip()
        if not nick or len(nick) > 20:
            c.send("IN")   # 昵称非法
            print(f"[聊天室:{self.port}] {c.addr[0]}:{c.addr[1]} 昵称非法: {nick!r}")
            return
        with self.lock:
            taken = any(
                cl is not c and cl.nick == nick for cl in self.clients.values()
            )
        if taken:
            c.send("EX")   # 昵称已被使用
            print(f"[聊天室:{self.port}] {c.addr[0]}:{c.addr[1]} 昵称被占用: {nick!r}")
            return
        c.nick = nick
        c.logged_in = True
        # 客户端 Timer 轮询 sub_40671A 用 strcmp 精确匹配 "OK", 而 OnReceive
        # 靠 NUL 提交缓冲。登录响应必须恰好是 "OK\x00"; 每条消息以 \x00
        # 结尾即可被独立提交, 无需延迟欢迎消息。
        c.send("OK")
        with self.lock:
            nicks = [cl.nick for cl in self.clients.values() if cl.logged_in]
        # 欢迎信息 + 在线列表
        c.send(color("*** lanqqd 公测聊天室欢迎你 !!!", 1))
        c.send(color("*** 当前在线: " + ", ".join(nicks), 4))
        print(f"[聊天室:{self.port}] {c.addr[0]}:{c.addr[1]} 登录成功 昵称={nick}")
        self.broadcast(color(f"*** {nick} 进入聊天室", 4), exclude=c)

    # ── 普通聊天 ──────────────────────────────────────
    def do_chat(self, c, text):
        if not text.strip():
            return
        # 广播: 昵称着色 + 消息
        self.broadcast(f"{color(c.nick, 1)}: {text}")

    # ── 命令 ──────────────────────────────────────────
    def do_command(self, c, line):
        cmd, _, rest = line.partition(" ")
        rest = rest.strip()
        if cmd == "/b":
            # 房间列表
            with self.lock:
                nicks = [cl.nick for cl in self.clients.values() if cl.logged_in]
            c.send(color("*** 当前在线: " + ", ".join(nicks), 4))
        elif cmd == "/olroom":
            # 开房: 客户端弹输入框, 随后发 "/j <房间名>" (sub_409958)
            self.do_roomlist(c)
        elif cmd == "/n":
            self.do_rename(c, rest)
        elif cmd == "/m":
            self.do_whisper(c, rest)
        elif cmd == "/i":
            c.send(color("*** 本服务器已进入, 无需邀请", 4))
        elif cmd == "/t":
            c.send(color(f"*** 房间标题已修改为: {rest}", 4))
        elif cmd == "/j":
            c.room = rest or "0"
            self.broadcast(color(f"*** {c.nick} 加入了房间 {c.room}", 4))
            c.send(color(f"*** 你已加入房间 {c.room}", 4))
        elif cmd == "/f":
            self.do_flag(c, rest)
        elif cmd in ("/q", "/quit"):
            c.conn.close()
        else:
            c.send(color("*** 未知命令: " + cmd, 4))

    def do_roomlist(self, c):
        """向本人发送默认房间列表 (原版五个默认房)"""
        for i, r in enumerate(DEFAULT_ROOMS, 1):
            c.send(color(f"*** [{i}] {r}", 1))

    def do_rename(self, c, new_nick):
        new_nick = new_nick.strip()
        if not new_nick or len(new_nick) > 20:
            c.send(color("*** 昵称非法", 4))
            return
        with self.lock:
            taken = any(
                cl is not c and cl.nick == new_nick for cl in self.clients.values()
            )
        if taken:
            c.send(color("*** 昵称已被使用", 4))
            return
        old = c.nick
        c.nick = new_nick
        self.broadcast(color(f"*** {old} 改名为 {new_nick}", 4))

    def do_whisper(self, c, rest):
        # 格式: OICQ_<号码> <内容>
        target, _, content = rest.partition(" ")
        content = content.strip()
        if not content:
            c.send(color("*** 用法: /m OICQ_号码 内容", 4))
            return
        target = target.split("_")[-1] if "_" in target else target
        with self.lock:
            t = next(
                (cl for cl in self.clients.values()
                 if cl.logged_in and cl.nick == target), None)
        if not t:
            c.send(color(f"*** 找不到用户 {target}", 4))
            return
        t.send(color(f"[私聊] {c.nick} 对你说: {content}", 2))
        c.send(color(f"[私聊] 你对 {t.nick} 说: {content}", 2))

    def do_flag(self, c, flag):
        # /f +l 锁定  /f -l 解锁  /f +s 秘密  /f -s 公开
        if flag in ("+l", "-l", "+s", "-s"):
            self.broadcast(color(f"*** 房间设置: /f {flag}", 4))
        else:
            c.send(color("*** 用法: /f +l /f -l /f +s /f -s", 4))

    def on_disconnect(self, c):
        if c.logged_in:
            self.broadcast(color(f"*** {c.nick} 离开了聊天室", 4))
            print(f"[聊天室:{self.port}] {c.addr[0]}:{c.addr[1]} 断开 ({c.nick})")


def run_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    s.listen(32)
    print(f"[聊天室] 监听 {HOST}:{port}")
    while True:
        conn, addr = s.accept()
        server = servers[port]
        threading.Thread(
            target=server.handle, args=(conn, addr), daemon=True).start()


servers = {}


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    ports = [port] + [p for p in EXTRA_PORTS if p != port]
    for p in ports:
        servers[p] = ChatRoomServer(p)
    threads = [threading.Thread(target=run_server, args=(p,), daemon=True)
               for p in ports]
    for t in threads:
        t.start()
    print(f"[聊天室] 共 {len(ports)} 个端口: {ports}")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[聊天室] 退出")


if __name__ == "__main__":
    main()
