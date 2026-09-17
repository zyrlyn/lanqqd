#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ 1999 服务端 (明文协议)
===========================
基于 oicq.asm 逆向分析实现。

协议特征: 与 QQ 2000 不同, 1999 版为明文传输——
无 TEA 加密、无加密头, data 为 ASCII/GBK 明文, 直接解析。

监听端口 : 8000 (UDP)

━━━ 协议格式（逆向结论）━━━

请求包（客户端→服务器, sub_406BE9 构造）:
    [0]      = 0x02
    [1]      = 0x01
    [2]      = 0x04
    [3..4]   = cmd      (2 字节, 大端)
    [5..6]   = seq      (2 字节, 大端, 客户端自增)
    [7..10]  = hostlong (4 字节, 大端)
               · 注册 0x03  : 0
               · 登录 0x13  : 用户账号 (oicq.asm: [esi+168h] = atol(号码))
               · 用户信息   : 被查号码
    [11..n]  = data
    [n+1]    = 0x03

响应包（服务器→客户端, sub_433359 解析）:
    [0]      = 0x02
    [1]      = 0x01
    [2]      = 0x04
    [3..4]   = cmd      (2 字节, 大端, 响应命令号)
    [5..6]   = seq      (2 字节, 大端, 回显请求的 seq)
    [7..n]   = data
    [n+1]    = 0x03

━━━ 命令表 ━━━
  cmd 0x03  注册(申请号码)   hostlong = 0
             data = 密码 + 0x1F + 昵称 + 0x1F + 性别 + 0x1F + ... (字段以 0x1F 分隔)
      响应  0x03(回显)       data = 新号码 ASCII / 失败码 (atoi 解析)
  cmd 0x04  修改个人设置      hostlong = 自己号码
             data = 密码 + 0x1F + 密码确认 + 0x1F + 资料字段...(0x1F 分隔, 尾部 0x1E 终止)
      响应  0x04(回显)       data = 保存后的资料 (客户端 case 3 校验 cmd 后 SetEvent 停止重发)
  cmd 0x13  登录             hostlong = 账号
             data = 标志("1") + 0x1F + 密码   (密码不验证)
      响应  0x13(回显)       data = 号码 ASCII / 失败码

★ 响应 cmd 必须与请求 cmd 相同: 客户端按 cmd-1 索引 off_4329E7 跳转表,
   cmd=0x03→case2(校验[esi+0F4h]seq,存[esi+148h]),
   cmd=0x13→case18(校验[esi+0F0h]seq,存[esi+14Ch])。
   返回别的 cmd 会落到不匹配的 case 走 default, 客户端永远等不到 SetEvent。
  cmd 0x06  查询用户信息     data = 号码字符串, hostlong = 号码
      响应  0x06(回显)       data = 号码 + 0x1E + 昵称 + 0x1E + 性别 + 0x1E + ...
                             (0x1E 分隔; 客户端 sub_419787 切分, 首字段=号码)
  cmd 0x02  查询用户信息     data = 号码 (登录成功后客户端发)
      响应  0x02(回显)       data = 同上格式 (存客户端 0x02 槽[128h])
  cmd 0x14  状态确认/握手    data = "0"/"1" (无隐身语义, 客户端收到响应不处理)
      响应  0x14(回显)       data = 空 (客户端以 "-1" 判定失败)
  cmd 0x01  登录确认(带密码) data = 密码
      响应  0x01(回显)       data = 空
  cmd 0x05  未知功能         data = 不定
      响应  0x05(回显)       data = 空
  cmd 0x0C  好友列表         hostlong = 自己号码
      响应  0x0C(回显)       data = 全服除自己外所有号码 + 0x1F + ... (0x1F 分隔)
                             全服仅自己时返回 "-1" (客户端显示"没有找到你的好友名单"后继续)
  cmd 0x10  获取群(聊天室)服务器列表   hostlong = 自己号码
             data = 页码/标志 ("0" + 0x1F + "0")
      响应  0x10            data = 条目1 + 0x1F + 条目2 + ...
                             条目 = 名称 + 0x1E + 地址 + 0x1E + 端口(十进制)
                             聊天室服务器独立于 QQ 服务器, 客户端拿到列表后直连

失败码约定（客户端 atoi 解析 data）:
  -1  -> 失败
  -2  -> 您的QQ版本已经过期
   0  -> 服务器无法给您分配QQ号码
"""

import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

# ── 配置 ────────────────────────────────────────────────
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 8000

# 聊天室服务器地址 (cmd 0x10 下发给客户端, 客户端直连此地址的 8001/8002)。
# 启动时由用户输入 (服务端本机 IP, 供局域网内其它电脑连接); 默认 127.0.0.1。
CHATROOM_IP = "127.0.0.1"
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packet.log")

# QQ 号码从 101 开始分配 (QQ 1999 客户端不校验号码长度)
NUMBER_START = 101

# ── 本地 Ollama AI 机器人 ───────────────────────────────
# 客户端给 BOT_QQ 发消息时, 服务端不转发, 改为调用本地 Ollama 的
# POST {OLLAMA_HOST}/api/chat, 并把回复以 0x78 包推回给发送方。
# 先 `ollama serve` 并 `ollama pull <模型>`; 启动本服务端时会自动探测
# 可用模型 (GET /api/tags) 供选择。全部可用环境变量预设, 也可启动时输入。
BOT_QQ = os.environ.get("BOT_QQ", "123")
BOT_NAME = os.environ.get("BOT_NAME", "AI助手")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "")
# 本地默认无需鉴权; 若前面挂了反代需要 key 才填
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "")
# 本地模型(尤其 CPU 推理)可能较慢, 超时放宽
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "180"))
# 每个发送者保留的上下文轮数 (1 轮 = 1 条用户消息 + 1 条助手回复)
OLLAMA_MAX_TURNS = int(os.environ.get("OLLAMA_MAX_TURNS", "8"))
# 是否让模型输出思维链 (deepseek-r1/qwen3 等推理模型); 默认关闭以提速
OLLAMA_THINK = os.environ.get("OLLAMA_THINK", "0") == "1"
# 不注入任何系统提示词: 本服务端只是通用 Ollama 客户端, 消息原样转发给模型,
# 模型表现完全由用户自己在消息里控制 (可在聊天窗口直接写指令/角色设定)。

# 字段分隔符: 单个 0x1F
# oicq.asm sub_452602(ecx, 1Fh, 1) -> _memset(ptr, 0x1F, 1), 分隔符就是 0x1F 一个字节
SEP = b"\x1f"

# 调试日志: 默认开启, 可用环境变量 QQ_DEBUG=0 关闭
DEBUG = os.environ.get("QQ_DEBUG", "1") == "1"

# 头/尾魔数
HEAD = bytes([0x02, 0x01, 0x04])
TAIL = 0x03


# ── 数据库 ──────────────────────────────────────────────
class UserDB:
    """用户数据库: users.json (纯 JSON, 密码不验证不存储)
    {
      "next": 102,
      "users": {
         "101": {"profile": "资料", "friends": ["102"], "reg_time": "...", "last_login": "..."}
      }
    }
    """

    def __init__(self, path):
        self.path = path
        self.data = {"next": NUMBER_START, "users": {}}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                if "next" not in self.data:
                    self.data["next"] = NUMBER_START
                if "users" not in self.data:
                    self.data["users"] = {}
            except Exception as e:
                print(f"[!] 读取数据库失败, 使用空库: {e}", file=sys.stderr)
                self.data = {"next": NUMBER_START, "users": {}}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[!] 保存数据库失败: {e}", file=sys.stderr)

    def allocate(self, profile):
        """分配一个新号码"""
        num = str(self.data["next"])
        self.data["next"] += 1
        self.data["users"][num] = {
            "profile": profile,
            "friends": [],  # 好友号码列表, 0x0C 返回
            "reg_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": "",
        }
        self.save()
        return num

    def get(self, num):
        return self.data["users"].get(num)

    def login(self, num):
        """登录: 只校验号码是否存在, 密码一律不验证"""
        u = self.get(num)
        if not u:
            return None
        u["last_login"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.save()
        return num


# ── 在线用户表 ──────────────────────────────────────────
# 号码 -> (ip, port); 由登录/发消息/查资料等可识别号码的请求注册。
# UDP 无连接, 不做超时清理; 同一号码再次注册即覆盖 (后登录者接管)。
ONLINE = {}

# 离线检测: QQ1999 下线时客户端从同一 (ip,port) 连发 3 次 0x01 登录确认。
# 记录每个地址的连续 0x01 次数, 5 秒窗内到 3 次即判定离线。
# 只依赖命令号, 不依赖 data 内容 (包内容可能变化)。
OFFLINE_WINDOW = 5.0
_offline_track = {}  # (ip,port) -> [连续次数, 上次时间戳]


def register_online(num, addr):
    """注册/刷新在线用户映射 (上线会重置该地址的离线检测计数)"""
    num = (num or "").strip()
    if num.isdigit():
        ONLINE[num] = addr
    _offline_track.pop(addr, None)


# ── 在线状态推送 (cmd 0x81) ─────────────────────────────
# 逆向 (oicq.asm):
#   sub_431F2A case 0x81: 校验 [esi+180h] != 包seq 后, 把 data 原样追加到
#     [主窗口+134h] CStringArray 队列 (超 300 条移除最旧), 再 SetEvent([esi+3Ch])。
#   sub_40F79C 消费队列: 按 0x1F 切首段 = QQ号 (atol), sub_426F82 查用户对象;
#     存在则把"剩余内容"交给 sub_40F5BD(用户, 剩余, 0x1F)。
#   sub_40F5BD 按 0x1F 再切 4 段:
#     段1 → atoi → [用户+24h] (%03d 显示)
#     段2 → atoi → [用户+14Ch]
#     段3 == "10" 且分隔符==0x1F 且 [用户+154h]!=0 → sndPlaySound("sound\\global.wav")
#     段3 == "30" → [用户+154h]=2 (标记离线); 其他 → [用户+154h]=1 (标记在线)
#     段4 → atoi → [用户+148h]
#   → 推送 data = QQ号 + 0x1F + 状态 + 0x1F + 计数 + 0x1F + ("10"/"30") + 0x1F + 标志
#   [用户+154h] 初值 0 时不会播 global.wav, 因此先补发 cmd 0x10 (sub_4049DE):
#     data = 状态数字 + 0x1F + "OICQ_" + QQ号 → 创建/更新用户对象, 刷新好友列表。
#     0x10 的队列条目 (纯QQ号) 被 sub_40F79C 消费时 sub_40F5BD 段3 为空 → [用户+154h]=1,
#     随后 0x81 条目才满足播放条件。
_push_seq = 0
_last_status = {}  # 号码 -> "1"(在线), 只在状态变化时推送; 下线后删除


def push_online_status(sock, qq, online):
    """向所有其他在线用户推送 cmd 0x10 + cmd 0x81 在线状态通知"""
    global _push_seq
    if sock is None or not qq:
        return
    _push_seq = (_push_seq + 1) & 0xFFFF
    flag = "1" if online else "0"
    code = "10" if online else "30"

    others = [(n, a) for n, a in list(ONLINE.items()) if n != qq]
    if not others:
        return

    # cmd 0x10: 创建/更新用户对象 (sub_4049DE: 状态数字 + 0x1F + OICQ_号码)
    d10 = (flag + "\x1fOICQ_" + qq).encode("latin-1", errors="replace")
    p10 = build_response(0x10, _push_seq, d10)
    # cmd 0x81: 触发 global.wav (sub_40F5BD 段3=="10") 或标记离线 (段3=="30")
    d81 = (qq + "\x1f" + flag + "\x1f0\x1f" + code + "\x1f" + flag).encode("latin-1", errors="replace")
    p81 = build_response(0x81, _push_seq, d81)

    for n, addr in others:
        sock.sendto(p10, addr)
        log_packet("->PUSH", addr, p10,
                   f"cmd=0x10 seq={_push_seq} 状态推送 {qq} {'上线' if online else '下线'} data={d10!r}")
        sock.sendto(p81, addr)
        log_packet("->PUSH", addr, p81,
                   f"cmd=0x81 seq={_push_seq} 状态推送 {qq} {'上线' if online else '下线'} data={d81!r}")
    print(f"[状态推送] {qq} {'上线' if online else '下线'} -> {sorted(n for n, _ in others)}")


def sync_online_to(sock, qq):
    """登录后把其他在线用户的状态静默同步给新用户 (0x10 + 0x81)。
    段3 用 "0" (非 "10"/"30"): sub_40F5BD 分支 [用户+154h]=1 标记在线但不播 global.wav,
    让新客户端好友头像亮起而不响提示音。"""
    global _push_seq
    if sock is None or not qq:
        return
    addr = ONLINE.get(qq)
    if not addr:
        return
    others = [n for n in sorted(ONLINE) if n != qq]
    if not others:
        return
    for n in others:
        _push_seq = (_push_seq + 1) & 0xFFFF
        d10 = ("1\x1fOICQ_" + n).encode("latin-1", errors="replace")
        p10 = build_response(0x10, _push_seq, d10)
        d81 = (n + "\x1f1\x1f0\x1f0\x1f1").encode("latin-1", errors="replace")
        p81 = build_response(0x81, _push_seq, d81)
        sock.sendto(p10, addr)
        log_packet("->PUSH", addr, p10,
                   f"cmd=0x10 seq={_push_seq} 登录同步 {n} 在线 data={d10!r}")
        sock.sendto(p81, addr)
        log_packet("->PUSH", addr, p81,
                   f"cmd=0x81 seq={_push_seq} 登录同步 {n} 在线 data={d81!r}")
    print(f"[登录同步] {qq} 已同步在线用户 {others}")


# ── 本地 Ollama 接入 ────────────────────────────────────
# 每个发送者一份对话历史: 号码 -> [{"role":..., "content":...}, ...]
_bot_sessions = {}
_bot_lock = threading.Lock()


def _ollama_headers():
    h = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        h["Authorization"] = "Bearer " + OLLAMA_API_KEY
    return h


def list_ollama_models():
    """探测本地 Ollama 已下载的模型 (GET /api/tags); 返回名称列表, 失败返回 []。"""
    try:
        req = urllib.request.Request(
            OLLAMA_HOST.rstrip("/") + "/api/tags",
            headers=_ollama_headers(),
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
        return [m.get("name") for m in (body.get("models") or []) if m.get("name")]
    except Exception as e:
        print(f"[!] 无法连接 Ollama ({OLLAMA_HOST}): {type(e).__name__}: {e}", file=sys.stderr)
        return []


def ask_ollama(user, text):
    """调用本地 Ollama /api/chat, 返回回复文本; 失败返回 None。
    纯标准库 urllib 实现, 无需安装 ollama/requests。
    响应结构: {"message": {"role":"assistant","content":"..."}, "done": true}"""
    global OLLAMA_MODEL
    if not OLLAMA_MODEL:
        return None

    with _bot_lock:
        hist = _bot_sessions.setdefault(user, [])
        hist.append({"role": "user", "content": text})
        # 只保留最近 OLLAMA_MAX_TURNS 轮 (1 轮 = user + assistant)
        if len(hist) > OLLAMA_MAX_TURNS * 2:
            del hist[:len(hist) - OLLAMA_MAX_TURNS * 2]
        # 不加任何 system 消息: 原样转发, 做通用客户端
        messages = list(hist)

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        # 推理模型(deepseek-r1/qwen3)默认会先输出 <think> 再回答, 白白多花数秒;
        # Ollama 新版支持关闭, 旧版会忽略该字段 (无副作用)。
        "think": OLLAMA_THINK,
    }, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_HOST.rstrip("/") + "/api/chat",
        data=payload,
        headers=_ollama_headers(),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))

    reply = (body.get("message") or {}).get("content", "")
    reply = (reply or "").strip()
    # 去掉 <think>...</think> (qwen3 等思考模型的思维链)
    reply = re.sub(r"<think>.*?</think>", "", reply, flags=re.S).strip()
    # 老客户端是单行纯文本窗口: 去掉换行/Markdown 标记
    reply = " ".join(reply.split())
    for ch in ("*", "`", "#", "_", "~", ">"):
        reply = reply.replace(ch, "")
    if reply:
        with _bot_lock:
            hist.append({"role": "assistant", "content": reply})
    return reply or None


def bot_reply_async(sock, sender, receiver, mtype, question):
    """工作线程: 调本地 Ollama 拿回复, 再用 cmd 0x78 推回给发送方。
    UDP 主循环是单线程的, 本地模型可能推理数秒~数十秒, 必须异步避免阻塞其它客户端。"""
    global _push_seq
    try:
        reply = ask_ollama(sender, question)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        print(f"[AI] HTTP {e.code} {detail}", file=sys.stderr)
        reply = None
    except Exception as e:  # 网络超时/模型未下载/解析失败等
        print(f"[AI] 调用失败: {type(e).__name__}: {e}", file=sys.stderr)
        reply = None

    if not reply:
        reply = "（模型这会儿没搭理我，稍后再试）"

    # 0x78 数据 = 发件人(BOT) + 0x1F + 类型 + 0x1F + 收件人(原发送方) + 0x1F + 日期 + 0x1F + 时间 + 0x1F + 内容
    # 内容必须 GBK 编码: QQ1999 客户端把 0x78 内容按 ANSI(GBK) 显示。
    now_date = time.strftime("%Y-%m-%d").encode("ascii")
    now_time = time.strftime("%H:%M:%S").encode("ascii")
    push_data = SEP.join([
        receiver.encode("latin-1", errors="replace"),
        mtype if isinstance(mtype, bytes) else str(mtype).encode("latin-1"),
        sender.encode("latin-1", errors="replace"),
        now_date, now_time,
        reply.encode("gbk", errors="replace"),
    ])
    addr = ONLINE.get(sender)
    if not addr:
        print(f"[AI] {sender} 已离线, 丢弃回复")
        return
    _push_seq = (_push_seq + 1) & 0xFFFF
    pkt = build_response(0x78, _push_seq, push_data)
    try:
        sock.sendto(pkt, addr)
        log_packet("->BOT", addr, pkt,
                   f"cmd=0x78 seq={_push_seq} AI回复 -> {sender} data={push_data[:50]!r}")
        print(f"[AI] {sender} 问: {question[:30]!r} -> 答: {reply[:60]!r}")
    except OSError as e:
        print(f"[AI] 发送失败: {e}", file=sys.stderr)


def ensure_bot_user(db):
    """确保机器人号码存在, 这样它会作为好友出现在客户端好友列表(cmd 0x0C)。"""
    if db.get(BOT_QQ) is not None:
        return
    # profile 与注册 0x03 一致: 0x1F 分隔, 依次 昵称/国家/省/市/... (客户端 sub_419787 按 0x1E 切)
    fields = [BOT_NAME, "中国", "北京", "北京", "-", "-", "-", "18", "女", "-",
              "bot@oicq", "-", "-", "-", "-", "互联网", "-", "0", "-", "-", "99",
              "-", "0", "我是本地 AI 助手，问我点什么吧。"]
    profile = "\x1f".join(fields)
    db.data["users"][BOT_QQ] = {
        "profile": profile,
        "friends": [],
        "reg_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": "",
    }
    db.save()
    print(f"[+] 已创建 AI 机器人号码 {BOT_QQ} ({BOT_NAME})")


# ── 日志 ────────────────────────────────────────────────
def debug(msg):
    """debug 级日志 (控制台), QQ_DEBUG=0 可关闭"""
    if DEBUG:
        print(f"[DEBUG] {msg}")


# ── 抓包日志 ────────────────────────────────────────────
def log_packet(direction, addr, raw, parsed):
    """把每个收发包写入 packet.log"""
    line = (
        f"[{time.strftime('%H:%M:%S')}] {direction} {addr[0]}:{addr[1]} "
        f"len={len(raw)}\n  hex: {raw.hex(' ')}\n  {parsed}\n"
    )
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


# ── 包解析/构造 ─────────────────────────────────────────
def parse_packet(raw):
    """解析请求包, 返回 dict; 非法返回 None"""
    if len(raw) < 12 or raw[0] != 0x02 or raw[1] != 0x01 or raw[2] != 0x04:
        return None
    if raw[-1] != TAIL:
        return None
    cmd = int.from_bytes(raw[3:5], "big")
    seq = int.from_bytes(raw[5:7], "big")
    hostlong = int.from_bytes(raw[7:11], "big")
    data = raw[11:-1]  # 去掉结尾 0x03
    return {"cmd": cmd, "seq": seq, "hostlong": hostlong, "data": data}


def build_response(cmd, seq, data):
    """构造响应包: 02 01 04 | cmd(BE) | seq(BE) | data | 03"""
    body = data if isinstance(data, bytes) else data.encode("latin-1")
    return HEAD + cmd.to_bytes(2, "big") + seq.to_bytes(2, "big") + body + bytes([TAIL])


def parse_login_data(data):
    """解析登录包 data: 标志 + 0x1F + 密码
    账号在 hostlong (不在 data)。
    返回 (标志, 密码bytes); 无 0x1F 分隔时整个 data 视为密码。
    """
    idx = data.find(SEP)
    if idx >= 0:
        flag = data[:idx].decode("latin-1", errors="replace")
        password = data[idx + 1:]
        return flag, password
    return "", data


# ── 命令处理 ────────────────────────────────────────────
def handle_packet(pkt, client_addr, db, sock=None):
    """处理一个请求包, 返回要发送的响应 bytes; 无需响应返回 None
    sock 用于主动推送: 0x08 转发 (向接收方发 0x78 包) 和 0x81 在线状态通知。"""
    cmd = pkt["cmd"]
    seq = pkt["seq"]
    data = pkt["data"]

    # 离线检测: 只有"连续"的 0x01 登录确认才累计, 中间夹了其它包就重置
    if cmd != 0x01:
        _offline_track.pop(client_addr, None)

    if cmd == 0x03:
        # ── 注册: hostlong=0, data = 密码 + 0x1F + 昵称 + 0x1F + ... ──
        # 首字段是密码, 服务端不验证不存储, 剥离后存资料
        if SEP in data:
            _pw, _, profile_bytes = data.partition(SEP)
        else:
            _pw, profile_bytes = b"", data
        profile = profile_bytes.decode("latin-1", errors="replace")
        num = db.allocate(profile)
        debug(f"注册 data 字段: {data.split(SEP)}")
        debug(f"注册 密码字段={_pw[:16]!r} 资料长度={len(profile_bytes)}")
        print(f"[注册] {client_addr[0]}:{client_addr[1]} 资料长度={len(profile_bytes)} -> 号码 {num}")
        # 响应 0x03 (回显请求 cmd): data = 新号码 ASCII
        return build_response(0x03, seq, num.encode("ascii"))

    if cmd == 0x04:
        # ── 修改个人设置: hostlong = 自己号码 ──
        # 真实包 (packet.log): cmd=0x04 seq=0 hostlong=102
        #   data = b'222\x1f222\x1f111\x1f-\x1f-\x1f...\x1f(个人说明)\x1e\x1f'
        #   → 前 2 字段 = 密码 / 密码确认 (服务端不验证不存储)
        #   → 字段2起 = 资料 (0x1F 分隔, 与注册 0x03 剥离首字段后的布局一致)
        #   → 尾部 0x1E 为资料终止符
        # 逆向 (oicq.asm):
        #   sub_439AA2 发送: [连接对象+0DCh] = seq (来自[ebx+8242h]), 包 seq 相同
        #     sub_431F2A case 3: 校验 [esi+0DCh]==响应seq, 把响应 data 存入 [esi+120h],
        #     然后 SetEvent([esi+48h]) → 等待线程停止
        #   sub_43AA0A 判定 (响应处理线程):
        #     atol(响应data 首段) == 自己号码([edi+168h]) → "服务器已经接受了你的新资料"
        #     atol(响应data 首段) == -2                  → "对不起"(版本过期)
        #     其他                                       → "请重试"+"服务器拒绝请求"
        #   → 响应 data 首字段必须是"自己号码", 否则必现"服务器拒绝请求"!
        num = str(pkt["hostlong"]) if pkt["hostlong"] > 0 else ""
        if not num or db.get(num) is None:
            print(f"[改资料] 号码 {num!r} 不存在 (拒绝)")
            return build_response(0x04, seq, b"-1")
        # 剥离前 2 个密码字段, 去掉尾部 0x1E 终止符, 存纯资料字节 (原样透传)
        sp = data.split(SEP, 2)
        profile = sp[2].rstrip(b"\x1e") if len(sp) > 2 else b""
        db.data["users"][num]["profile"] = profile.decode("latin-1", errors="replace")
        db.save()
        register_online(num, client_addr)
        print(f"[改资料] 号码 {num} 保存 资料长度={len(profile)} "
              f"字段数={profile.count(SEP) + 1 if profile else 0}")
        # 响应 data 首字段 = 自己号码 (sub_43AA0A 以此判定成功) + 保存后的资料
        return build_response(0x04, seq, num.encode("latin-1") + SEP + profile)

    if cmd == 0x13:
        # ── 登录: hostlong = 账号, data = 标志("0"/"1") + 0x1F + 密码 (密码不验证) ──
        # 标志只是握手值 (QQ1999 无隐身), 登录成功即视为在线并推上线。
        flag, password = parse_login_data(data)
        num = str(pkt["hostlong"]) if pkt["hostlong"] > 0 else None
        if not num:
            # 兼容: hostlong 无效时回退, 尝试从 data 中找纯数字
            text = data.decode("latin-1", errors="replace")
            digits = "".join(ch for ch in text if ch.isdigit())
            num = digits or None
        debug(f"登录 data: 标志={flag!r} 密码={password[:16]!r} hostlong账号={num}")
        if not num:
            print(f"[登录] {client_addr[0]}:{client_addr[1]} 无法解析账号 (hostlong=0, data 无数字)")
            return build_response(0x13, seq, b"-1")
        ok = db.login(num)
        if ok:
            was = _last_status.get(num)
            register_online(num, client_addr)
            # QQ1999 无隐身; 登录 data 标志 "0"/"1" 只是握手值, 登录即视为在线。
            _last_status[num] = "1"
            print(f"[登录] 号码 {num} 成功 (密码不验证) 在线={sorted(ONLINE)}")
            # 先把已在线用户的状态同步给新登录用户 (好友头像亮起), 再广播新用户上线。
            sync_online_to(sock, num)
            if was != "1":
                push_online_status(sock, num, True)
            return build_response(0x13, seq, num.encode("ascii"))
        print(f"[登录] 号码 {num} 失败 (不存在)")
        return build_response(0x13, seq, b"-1")

    if cmd == 0x06 or cmd == 0x02:
        # ── 查询用户信息 (0x06 / 0x02): data/hostlong = 号码 ──
        # 0x06: 查资料, 客户端解析到 0x06 槽[154h]
        # 0x02: 登录成功后查自己资料, 客户端解析到 0x02 槽[128h]
        # 资料格式: 号码 + 0x1E + 昵称 + 0x1E + 性别 + 0x1E + ... (0x1E 分隔)
        # oicq.asm sub_419787 按 0x1E 切分: token1→号码, token2→昵称, token3→性别...
        num_txt = data.decode("latin-1", errors="replace").strip()
        if not num_txt.isdigit():
            num_txt = str(pkt["hostlong"])
        u = db.get(num_txt)
        if u:
            register_online(num_txt, client_addr)
            profile = u["profile"]  # 注册资料字段, 0x1F 分隔, 已去密码
            fields = profile.split("\x1f")
            body = num_txt.encode("latin-1") + b"\x1e" + b"\x1e".join(
                f.encode("latin-1", errors="replace") for f in fields)
            print(f"[用户信息] 号码 {num_txt} -> 字段数={len(fields)} 长度={len(body)}")
            return build_response(cmd, seq, body)
        print(f"[用户信息] 号码 {num_txt} 不存在")
        return build_response(cmd, seq, b"")

    if cmd == 0x14:
        # ── 状态确认/握手: data = "0"/"1" ──
        # QQ1999 无隐身; 客户端收到 0x14 响应后不处理 (oicq.asm sub_4051E1 仅释放字符串),
        # 因此这里不更新状态、不触发在线状态推送。
        # 在线/离线仅由 登录(0x13 推上线) 和 连续 3 次 0x01 判定(推下线) 驱动。
        print(f"[状态设置] {client_addr[0]}:{client_addr[1]} data={data!r}")
        return build_response(0x14, seq, b"")

    if cmd == 0x01:
        # ── 登录确认/上线(带密码): data = 密码 ──
        # QQ1999 下线特征: 客户端从同一地址连发 3 次 0x01 登录确认 (data 内容可变,
        # 只看命令号不看内容)。5 秒窗内累计 3 次 → 把该地址对应的在线号码标离线。
        print(f"[登录确认] {client_addr[0]}:{client_addr[1]} data={data[:16]!r}")
        now = time.time()
        prev = _offline_track.get(client_addr)
        if prev and now - prev[1] <= OFFLINE_WINDOW:
            prev[0] += 1
            prev[1] = now
        else:
            prev = _offline_track[client_addr] = [1, now]
        if prev[0] >= 3:
            _offline_track.pop(client_addr, None)
            offlined = [n for n, a in list(ONLINE.items()) if a == client_addr]
            for n in offlined:
                if _last_status.get(n) == "1":
                    push_online_status(sock, n, False)
                _last_status.pop(n, None)
                del ONLINE[n]
            print(f"[离线] 号码 {offlined} 下线 (连发3次登录确认) 在线={sorted(ONLINE)}")
        return build_response(0x01, seq, b"")

    if cmd == 0x05:
        # ── 未知功能: 响应 cmd 回显, data 空 ──
        print(f"[cmd 0x05] {client_addr[0]}:{client_addr[1]} data={data!r}")
        return build_response(0x05, seq, b"")

    if cmd == 0x0C:
        # ── 好友列表: hostlong = 自己号码 ──
        # 响应 data = 全服除自己外所有号码 + 0x1F + ... (0x1F 分隔)
        # 全服仅自己时返回 "-1": 客户端显示"没有找到你的好友名单"后仍可继续完成启动。
        # oicq.asm: 请求构造 hostlong=atol(号码), seq→[esi+0E8h];
        #   case11 loc_43237F 校验[esi+0E8h]seq, data 存 [esi+164h];
        #   sub_40AFF1 atoi(data)==-1 → "没有找到你的好友名单",
        #   否则按 0x1F 切分好友号码, 逐个发 0x06 查资料 → "已经将好友列表读取到本地"
        num_txt = str(pkt["hostlong"]) if pkt["hostlong"] > 0 else None
        if not num_txt:
            text = data.decode("latin-1", errors="replace")
            digits = "".join(ch for ch in text if ch.isdigit())
            num_txt = digits or None
        if not num_txt:
            return build_response(0x0C, seq, b"-1")
        if db.get(num_txt) is None:
            print(f"[好友列表] 号码 {num_txt} 不存在 (返回 -1)")
            return build_response(0x0C, seq, b"-1")
        register_online(num_txt, client_addr)
        others = [n for n in db.data["users"] if n != num_txt]
        if others:
            body = b"\x1f".join(n.encode("latin-1", errors="replace") for n in others)
            print(f"[好友列表] 号码 {num_txt} -> 全服其他人: {others}")
            return build_response(0x0C, seq, body)
        print(f"[好友列表] 号码 {num_txt} 全服仅此一人 (返回 -1)")
        return build_response(0x0C, seq, b"-1")

    if cmd == 0x08:
        # ── 发送消息(中转) ──
        # 请求: hostlong = 发送方号码(自己)
        #       data   = 接收方 + 0x1F + 标志("0") + 0x1F + 内容 + 0x1F + 日期 + 0x1F + 时间 + 0x1F + 字号("9")
        # 逆向 (oicq.asm + 真实抓包):
        #   sub_436DE7 发送线程构造: hostlong=[eax+168h](登录号码=发送方), data 组合串以接收方号码开头
        #   真实包: cmd=0x08 hostlong=101 data=b'103\x1f0\x1f0\x1f2026-08-20\x1f01:29:44\x1f9'
        #           101发→段1=103(接收方), hostlong=101(发送方)
        #   loc_4321FE  (0x08 响应): 响应 data 按 0x1F 切首段 atol, 与确认列表 {号码,seq} 匹配 → SetEvent
        #     → ACK 的 data 首段必须是接收方号码!
        #   loc_43283E  (0x78 推送=接收消息): data 段1=发件人号码(atol→[obj+0] 查会话)
        #     段2=类型(atoi→[obj+4]) 段3=对方号码(atol→[obj+8]) 段4起=内容(→[obj+18h])
        #     sub_40E535 从 [obj+94h] 队列消费 → sub_40E691 用 [obj+0] 查会话, 用 类型+11 查表:
        #       case 0 = 聊天 (存记录+sub_427E23 显示 "(%s %s) 内容" + 播 msg.wav)
        #       case -3 = 接收文件;  case -1 有 [esi+10h]==0 严格条件极易被丢弃!
        #     → 段1=发件人号码, 段2=原类型(聊天=0), 段3=对方号码, 段4=日期, 段5=时间, 段6=内容
        #   注意: 0x80 是"发送消息"命令(客户端→服务器), 推送必须用 0x78!
        # data 真实布局: 接收方 + 0x1F + 类型 + 0x1F + 标志 + 0x1F + 日期 + 0x1F + 时间 + 0x1F + 内容
        #   例: b'101\x1f0\x1f195\x1f2026-08-20\x1f01:43:42\x1f000'
        #   内容 = "时:分:秒" 之后的字段! (纯字节透传, 不做任何编码转换)
        sp = data.split(SEP, 5)
        receiver = sp[0].decode("latin-1", errors="replace").strip()
        sender = str(pkt["hostlong"]) if pkt["hostlong"] > 0 else ""
        mtype = sp[1] if len(sp) > 1 else b"0"
        date = sp[3] if len(sp) > 3 else b""
        msg_time = sp[4] if len(sp) > 4 else b""
        content = sp[5] if len(sp) > 5 else b""
        register_online(sender, client_addr)
        print(f"[发消息] {sender} -> {receiver} data={data[:60]!r}")

        # ACK 给发送方: cmd 0x08, seq 原样, data 首段=接收方号码 (发送线程按此匹配停止重发)
        ack = build_response(0x08, seq, receiver.encode("ascii", errors="replace") + SEP + data)

        # ── 发给 AI 机器人: 不转发, 交给本地 Ollama 异步回复 ──
        if receiver == BOT_QQ:
            question = content.decode("gbk", errors="replace").strip()
            if question and sock:
                threading.Thread(
                    target=bot_reply_async,
                    args=(sock, sender, receiver, mtype, question),
                    daemon=True,
                ).start()
                print(f"[发消息] {sender} -> AI机器人({BOT_QQ}) 已转交 Ollama: {question[:40]!r}")
            else:
                print(f"[发消息] {sender} -> AI机器人({BOT_QQ}) 空消息, 忽略")
            return ack

        target = ONLINE.get(receiver)
        if target:
            # 原 data = 接收方 + 0x1F + 类型 + 0x1F + 标志 + 0x1F + 日期 + 0x1F + 时间 + 0x1F + 内容
            # 0x78 重组: 发送方 + 0x1F + 类型 + 0x1F + 接收方 + 0x1F + 日期 + 0x1F + 时间 + 0x1F + 内容
            #   (类型保持原值: 0=聊天走 case 0, -3=文件走 case -3; 段2 绝不能改成 -1!)
            #   内容/日期/时间/类型 全部使用请求中的原始字节, 绝不做编解码!
            push_data = SEP.join([
                sender.encode("latin-1", errors="replace"), mtype,
                receiver.encode("latin-1", errors="replace"), date,
                msg_time, content,
            ])
            fwd = build_response(0x78, seq, push_data)
            if sock:
                sock.sendto(fwd, target)
                log_packet("->FWD", target, fwd,
                           f"cmd=0x78 seq={seq} push(接收方={receiver}) data={push_data[:50]!r}")
            print(f"[发消息] {sender} -> {receiver} 转发成功 ({target[0]}:{target[1]})")
        else:
            # 接收方不在线: 回 ACK 之外, 模拟接收方自动回复一条离线提示。
            # 这条消息是服务端生成的假消息(非透传), 必须用 GBK 编码——
            # QQ1999 客户端把收到的 0x78 内容按 ANSI(GBK) 显示。
            now_date = time.strftime("%Y-%m-%d").encode("ascii")
            now_time = time.strftime("%H:%M:%S").encode("ascii")
            auto_reply = "这家伙离线了，给他发消息干啥".encode("gbk", errors="replace")
            push_data = SEP.join([
                receiver.encode("latin-1", errors="replace"),  # 段1=发件人=接收方(模拟)
                mtype,                                          # 段2=类型(0=聊天)
                sender.encode("latin-1", errors="replace"),    # 段3=收件人=原发送方
                now_date, now_time, auto_reply,                 # 段4=日期 段5=时间 段6=内容(GBK)
            ])
            auto_pkt = build_response(0x78, seq, push_data)
            if sock:
                sock.sendto(auto_pkt, client_addr)
                log_packet("->FWD", client_addr, auto_pkt,
                           f"cmd=0x78 seq={seq} 离线自动回复(模拟 {receiver}) data={push_data[:50]!r}")
            print(f"[发消息] {sender} -> {receiver} 不在线, 已回 ACK 并模拟对方自动回复 "
                  f"(在线={sorted(ONLINE)})")
        return ack

    if cmd == 0x10:
        # ── 获取群(聊天室)服务器列表 ──
        # 注意: 聊天室服务器 ≠ QQ 服务器! 客户端拿到列表后直接连聊天室服务器。
        # 逆向 (oicq.asm):
        #   sub_40691E (聊天室入口 OnInitDialog) 发请求: cmd=0x10 hostlong=自己
        #     data=b'0\x1f0' (页码/标志), [连接+114h]=seq
        #   sub_431F2A case 15 (loc_432418): 校验 [esi+114h]==seq → SetEvent
        #     → 响应 data 原样存 [连接+16Ch]
        #   sub_406A9C (解析线程): 把 data 按 0x1F 切服务器条目 → CStringArray
        #   sub_407570 (聊天室窗口): 每条目按 0x1E 再切:
        #     段1=名称(显示) 段2=地址 段3=atoi→端口
        #   → 响应 data = 条目1 + 0x1F + 条目2 + ... (无尾部空段)
        #     每个条目 = 名称 + 0x1E + 地址 + 0x1E + 端口(十进制)
        # 包解析 sub_433359 用 strrchr(data,0x03) 定界, 0x1E/0x1F 可安全出现在 data 中。
        # 列表为空时客户端弹"没有查找到可用的聊天服务器"。
        name = "lanqqd公测聊天室".encode("gbk", errors="replace")
        ip = CHATROOM_IP.encode("ascii", errors="replace")
        entries = [
            name + b"\x1e" + ip + b"\x1e" + b"8001",
            name + b"\x1e" + ip + b"\x1e" + b"8002",
        ]
        body = b"\x1f".join(entries)
        print(f"[群服务器列表] 响应 {client_addr[0]}:{client_addr[1]} "
              f"条目数={len(entries)} body={body[:60]!r}")
        return build_response(0x10, seq, body)

    # 未知命令: 只记录日志
    print(f"[未知命令 0x{cmd:02X}] from {client_addr[0]}:{client_addr[1]}")
    return None


# ── 主循环 ──────────────────────────────────────────────
def main():
    # Windows 下确保日志文件使用 UTF-8 且即时刷新
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    print("=" * 60)
    print(" QQ 1999 服务端 + 本地 Ollama AI  (明文协议, 基于 oicq.asm 逆向)")
    print(f" 监听 UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f" 数据库: {DB_FILE}")
    print(f" 抓包日志: {LOG_FILE}")
    print("=" * 60)

    # 启动时询问聊天室服务器 IP (下发给客户端的地址, 局域网用本机 IP)
    global CHATROOM_IP, OLLAMA_MODEL
    try:
        inp = input(f"聊天室服务器地址 (客户端连接用, 默认 {CHATROOM_IP}): ").strip()
        if inp:
            CHATROOM_IP = inp
            print(f"[+] 聊天室服务器地址: {CHATROOM_IP}")
    except (EOFError, KeyboardInterrupt):
        print(f"\n[+] 未输入, 使用默认: {CHATROOM_IP}")

    # Ollama 模型选择: 环境变量 OLLAMA_MODEL 已设置则直接用, 否则探测 /api/tags 供选择
    print(f"\n[·] 正在探测 Ollama ({OLLAMA_HOST}) ...")
    models = list_ollama_models()
    if models and not OLLAMA_MODEL:
        print(f"[+] 本地已有 {len(models)} 个模型:")
        for i, name in enumerate(models, 1):
            print(f"    {i}. {name}")
        try:
            sel = input(f"选择模型 (1-{len(models)}, 默认 1): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(models):
                OLLAMA_MODEL = models[int(sel) - 1]
            elif sel:
                OLLAMA_MODEL = sel
            else:
                OLLAMA_MODEL = models[0]
        except (EOFError, KeyboardInterrupt):
            OLLAMA_MODEL = models[0]
        print(f"[+] 已选择模型: {OLLAMA_MODEL}")
    elif not OLLAMA_MODEL:
        print("[!] 未探测到 Ollama 或没有已下载模型 (先 ollama serve && ollama pull <模型>)")
        try:
            OLLAMA_MODEL = input("手动输入模型名 (直接回车跳过 AI): ").strip()
        except (EOFError, KeyboardInterrupt):
            OLLAMA_MODEL = ""

    db = UserDB(DB_FILE)
    if OLLAMA_MODEL:
        ensure_bot_user(db)
        print(f"[+] AI 已启用: 机器人号码 {BOT_QQ} ({BOT_NAME}), Ollama 模型 {OLLAMA_MODEL}")
    else:
        print("[-] 未配置模型, 机器人不启用")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print("[+] 服务已启动, 等待客户端...\n")

    while True:
        try:
            raw, addr = sock.recvfrom(65535)
        except KeyboardInterrupt:
            print("\n[-] 已停止")
            break
        except OSError as e:
            print(f"[!] 接收错误: {e}", file=sys.stderr)
            continue

        pkt = parse_packet(raw)
        if not pkt:
            log_packet("<-REQ", addr, raw, "无法解析 (头部/尾部不匹配)")
            continue

        parsed_txt = (
            f"cmd=0x{pkt['cmd']:02X} seq={pkt['seq']} hostlong={pkt['hostlong']} "
            f"data_len={len(pkt['data'])} data={pkt['data'][:40]!r}"
        )
        log_packet("<-REQ", addr, raw, parsed_txt)

        resp = handle_packet(pkt, addr, db, sock)
        if resp:
            sock.sendto(resp, addr)
            log_packet("->RES", addr, resp,
                       f"cmd=0x{(resp[3] << 8 | resp[4]):02X} seq={(resp[5] << 8 | resp[6])} "
                       f"data_len={len(resp) - 12} data={resp[7:-1][:40]!r}")


if __name__ == "__main__":
    main()
