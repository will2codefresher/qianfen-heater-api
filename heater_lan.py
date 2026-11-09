#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""heater_lan.py —— 前锋热水器（com.gwcd.Chiffo.floor）局域网 UDP 直连客户端。

协议来自真实抓包（apk_analysis/pair4.pcap、power3.pcap）：
  UDP 1194，请求/响应 16 字节头 + payload：
    [0]      0x32 请求 / 0x30 响应
    [1:3]    序号（大端，逐包 +1）
    [3:6]    0
    [6:8]    会话 id（由设备在登录应答里下发）
    [8:10]   80 00
    [10]     1e
    [11:13]  14 00
    [13:15]  命令（小端：f2=登录, f3=查询, f4=控制）
    [15]     payload 长度

登录（f2，三步）：
  1) req1 = 01 01 02 00 | nonce1(4, 随机) | SN(8, 大端) | f2ddf0383b1738a7ffffffff9d90ab29 | tail8
  2) rsp1 = 03 00 00 00 | nonce2(4) | 16*00
  3) req2 = 04 00 00 03 | MD5(nonce1 || nonce2 || MD5(password)) | tail8 | 0064000400000003
  rsp2: 05 00 00 00 ... 设备信息（含昵称 "chiffo"）

控制（f4）：payload = 09 | 01 00 00 00 | 02 00 0b 00 | 02 00 10 00 | 01 00 0c | RF 帧
  RF 帧 = aa aa 08 00 00 06 <cmd16> <ck16> 55 55
  已确认：温度+ = 04 00，温度- = 00 00，电源切换 = 09 00（校验待补）

用法：
    python heater_lan.py pair   --sn 826000023150 --pwd td1234567
    python heater_lan.py status --sn ... --pwd ...
    python heater_lan.py power  --sn ... --pwd ...          # 切换一次
    python heater_lan.py cycle  --sn ... --pwd ...          # 关→开，最终保证开

SN 与密码缺省从同目录 config.ini 的 [heater] 分组读取；首次运行（无配置文件或字段为空）
会提示输入，并自动写回 config.ini。
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional, Tuple

DEFAULT_HOST = "192.168.3.83"
DEFAULT_PORT = 1194

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
CONFIG_SECTION = "heater"


def load_config(path: str = CONFIG_PATH) -> dict:
    """读取 config.ini 里的 sn/pwd；文件或字段缺失时返回空字符串。"""
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    return {
        "sn": parser.get(CONFIG_SECTION, "sn", fallback="").strip(),
        "pwd": parser.get(CONFIG_SECTION, "pwd", fallback="").strip(),
    }


def save_config(sn, pwd, path: str = CONFIG_PATH) -> None:
    """把 sn/pwd 写回 config.ini（保留文件里其它分组）。"""
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    if not parser.has_section(CONFIG_SECTION):
        parser.add_section(CONFIG_SECTION)
    parser.set(CONFIG_SECTION, "sn", str(sn))
    parser.set(CONFIG_SECTION, "pwd", str(pwd))
    with open(path, "w", encoding="utf-8") as fp:
        parser.write(fp)


def resolve_credentials(sn: Optional[str] = None, pwd: Optional[str] = None) -> Tuple[str, str]:
    """按 参数 > 环境变量 > config.ini > 交互输入 的顺序取 SN 和密码。

    拿到的值写回 config.ini：配置文件不存在、或本次是用户手工输入时都会保存。
    """
    cfg = load_config()
    missing_file = not os.path.exists(CONFIG_PATH)
    prompted = False
    if not sn:
        sn = cfg["sn"]
    if not pwd:
        pwd = os.environ.get("HEATER_PWD", "") or cfg["pwd"]
    if not sn:
        sn = input("未找到设备 SN，请输入: ").strip()
        prompted = True
    if not pwd:
        pwd = input("未找到设备密码，请输入: ").strip()
        prompted = True
    if sn and pwd and (prompted or missing_file):
        save_config(sn, pwd)
    return sn, pwd


_CFG = load_config()
DEFAULT_SN = _CFG["sn"]
DEFAULT_PWD = _CFG["pwd"]

TAIL8 = bytes.fromhex("07ea0b050e3a1008")
CONST_A = bytes.fromhex("f2ddf0383b1738a7ffffffff9d90ab29")
REQ2_TAIL = bytes.fromhex("0064000400000003")


def md5(*parts: bytes) -> bytes:
    h = hashlib.md5()
    for p in parts:
        h.update(p)
    return h.digest()


class HeaterError(RuntimeError):
    pass


def crc16_ccitt(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def rf_frame(cmd16: int) -> bytes:
    """构造 RF 控制帧：aa aa 08 00 00 06 <cmd16 LE> <crc16 CCITT LE> 55 55。

    已用三个实抓帧校验（电源 09 00 / 温度+ 04 00 / 温度- 00 00）。
    """
    body = bytes.fromhex("aaaa08000006") + struct.pack("<H", cmd16)
    return body + struct.pack("<H", crc16_ccitt(body)) + bytes.fromhex("5555")


def build_header(seq: int, session: int, cmd: int, payload_len: int) -> bytes:
    return (
        bytes([0x32])
        + struct.pack(">H", seq & 0xFFFF)
        + b"\x00\x00\x00"
        + struct.pack(">H", session & 0xFFFF)
        + b"\x80\x00\x1e\x14\x00"
        + struct.pack("<H", cmd)
        + bytes([payload_len])
    )


@dataclass
class Heater:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    sn: int | str = DEFAULT_SN
    pwd: str = DEFAULT_PWD
    timeout: float = 2.0

    def __post_init__(self) -> None:
        self.sock: Optional[socket.socket] = None
        self.session = 0
        self.seq = 0
        self.device_info: bytes = b""
        self.last_status: bytes = b""

    # ---------------------------------------------------------------- 网络
    def _ensure_socket(self) -> None:
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

    def _send(self, cmd: int, payload: bytes) -> bytes:
        self._ensure_socket()
        pkt = build_header(self.seq, self.session, cmd, len(payload)) + payload
        self.sock.send(pkt)
        data = self.sock.recv(4096)
        # 跳过心跳/推送，只取同命令的响应
        for _ in range(4):
            if len(data) >= 16 and data[0] == 0x30 and data[15] == len(data) - 16 and \
                    struct.unpack("<H", data[13:15])[0] == cmd:
                break
            data = self.sock.recv(4096)
        self.seq = (self.seq + 1) & 0xFFFF
        return data

    # ---------------------------------------------------------------- 登录
    def login(self) -> bytes:
        nonce1 = os.urandom(4)
        payload1 = (
            bytes.fromhex("01010200")
            + nonce1
            + int(self.sn).to_bytes(8, "big")
            + CONST_A
            + TAIL8
        )
        rsp1 = self._send(0xF2, payload1)
        if len(rsp1) < 24 or rsp1[16:20] != b"\x03\x00\x00\x00":
            raise HeaterError("登录第一步被拒绝: %s" % rsp1.hex())
        self.session = struct.unpack(">H", rsp1[6:8])[0]
        nonce2 = rsp1[20:24]
        digest = md5(nonce1, nonce2, hashlib.md5(self.pwd.encode()).digest())
        payload2 = bytes.fromhex("04000003") + digest + TAIL8 + REQ2_TAIL
        rsp2 = self._send(0xF2, payload2)
        if len(rsp2) < 20 or rsp2[16:20] != b"\x05\x00\x00\x00":
            raise HeaterError("登录失败（口令错误？）: %s" % rsp2.hex())
        self.device_info = rsp2
        # 设备按“上一条序号+1”校验：登录两包都是 seq=0，之后从 1 开始
        self.seq = 1
        return rsp2

    # ---------------------------------------------------------------- 查询
    def query(self) -> bytes:
        rsp = self._send(0xF3, bytes.fromhex("01000000"))
        self.last_status = rsp
        return rsp

    def status(self) -> dict:
        rsp = self.query()
        payload = rsp[16:]
        info = {"raw": payload.hex(), "online": True}
        try:
            info.update(self.read_push())
        except (HeaterError, socket.timeout, OSError) as exc:
            info["push_error"] = str(exc)
        # 已知格式：02 00 00 00 | 00 03 | len | 数据...；数据里含 RF 帧
        frame = None
        idx = payload.find(bytes.fromhex("aaaa"))
        if idx >= 0:
            frame = payload[idx:]
            info["rf_frame"] = frame.hex()
        info["power"] = decode_power(frame) if frame else "unknown"
        info["set_temp"] = decode_set_temp(frame) if frame else None
        return info

    # ---------------------------------------------------------------- 详情
    def detail(self) -> dict:
        """查询设备详情页（固件/服务器/IP/已连手机等），返回 TLV 解析结果。"""
        # 设备要求先做 08 01 初始化（App 登录后也是这个顺序）
        self._send(0xF4, bytes.fromhex("0801000000") + bytes.fromhex("01000100010000"))
        self._send(0xF4, bytes.fromhex("0801000000") + bytes.fromhex("02000c0007000400010000"))
        req = (
            bytes.fromhex("0803000000")
            + bytes.fromhex("01000700")
            + bytes.fromhex("02000000")
            + bytes.fromhex("01000300")
            + bytes.fromhex("0c000000")
            + bytes.fromhex("01000300")
            + bytes.fromhex("640000")
        )
        rsp = self._send(0xF4, req)
        return parse_tlvs(rsp[16:])

    def read_push(self, timeout: float = 6.0) -> dict:
        """订阅并读取一帧 77B 状态推送，解出温度/电源位。
        帧结构（实测）：aa aa 1d 00 00 | f8 fe xx xx | ff f1 ff ff | 00 |
                        setpoint(BCD) | current(BCD) | ... | 55 55
        """
        self._send(0xF4, bytes.fromhex("0801000000") + bytes.fromhex("01000100010000"))
        end = time.time() + timeout
        while time.time() < end:
            data = self.sock.recv(4096)
            if len(data) < 16 or data[13:15] != b"\xf4\x00" or data[15] < 0x3d:
                continue
            payload = data[16:]
            idx = payload.find(b"\xaa\xaa")
            if idx < 0 or len(payload) < idx + 33:
                continue
            frame = payload[idx:idx + 33]
            def bcd(x):
                return (x >> 4) * 10 + (x & 0x0F) if (x >> 4) <= 9 and (x & 0x0F) <= 9 else None
            out = {"frame": frame.hex()}
            out["set_temp"] = bcd(frame[14])
            out["current_temp"] = bcd(frame[15])
            out["bits"] = frame[5:9].hex()
            return out
        raise HeaterError("no push frame")

    def power_state(self, wait: float = 4.0) -> str:
        """实验性：用推送帧判断开关机。

        规律（两组带 UI 标注的样本）：
          - 开机帧 frame[8] 的 bit3 置位（0xb7），关机帧清零（0xaf）；
          - 关机后设备会停止周期推送。
        返回 'on' / 'off' / 'unknown'。
        """
        try:
            frames = self.collect_frames(wait)
        except (HeaterError, socket.timeout, OSError):
            return "unknown"
        if not frames:
            return "off"
        last = bytes.fromhex(frames[-1])
        idx = last.find(b"\xaa\xaa")
        if idx < 0 or len(last) < idx + 9:
            return "unknown"
        return "on" if (last[idx + 8] & 0x08) else "off"

    def ensure_on(self, tries: int = 4) -> bool:
        """反复 toggle 直到能收到状态推送（开机时设备会周期推送），返回是否成功。"""
        for i in range(tries):
            if self.is_on(6.0):
                return True
            self.toggle(1.0)
            time.sleep(1.0)
        return self.is_on(6.0)

    def collect_frames(self, seconds: float = 4.0) -> list:
        try:
            self._send(0xF4, bytes.fromhex("0801000000") + bytes.fromhex("01000100010000"))
        except (socket.timeout, TimeoutError):
            pass
        end = time.time() + seconds
        out = []
        while time.time() < end:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if len(data) >= 16 and data[13:15] == b"\xf4\x00" and data[15] >= 0x3d:
                out.append(data[16:].hex())
        return out

    def detail_raw(self) -> dict:
        """设备信息查询（f4 08 03）：返回原始字节 + 能确认的字段。

        已确认（对比 App 详情页）：服务器域名、MAC 出现在应答里；
        IP/WiFi/运行时长/已连手机数 不在该应答中。
        """
        rsp = self._send(0xF4, bytes.fromhex(
            "0803000000" "01000700" "02000000" "01000300"
            "0c000000" "01000300" "640000"))
        payload = rsp[16:]
        info = {"raw": payload.hex()}
        # 服务器域名：最长的可打印 ASCII 串
        import re as _re
        strs = _re.findall(rb"[ -~]{6,}", payload)
        domains = [x for x in strs if b"." in x and b"galaxy" in x or b".com" in x]
        if domains:
            info["server"] = max(domains, key=len).decode("ascii", "replace").strip("\x00")
        idx = payload.find(b"\x00\x2e\x00\x06")
        if idx >= 0 and idx + 10 <= len(payload):
            mac = payload[idx + 4: idx + 10]
            info["mac"] = ":".join("%02x" % b for b in mac)
        return info

    # ---------------------------------------------------------------- 控制
    def _control(self, rf: bytes) -> bytes:
        payload = (
            bytes.fromhex("0901000000")
            + bytes.fromhex("02000b00")
            + bytes.fromhex("02001000")
            + bytes.fromhex("01000c")
            + rf
        )
        try:
            return self._send(0xF4, payload)
        except (socket.timeout, TimeoutError):
            # 设备有时不回 ACK（尤其关机瞬间），命令通常仍然生效
            return b""

    def toggle(self, wait: float = 1.0) -> None:
        """电源切换（RF cmd 0x0009，实测为 toggle）。"""
        self._control(rf_frame(0x0009))
        time.sleep(wait)

    def power_on(self, wait: float = 1.0) -> None:
        self.toggle(wait)

    def power_off(self, wait: float = 1.0) -> None:
        self.toggle(wait)

    def cycle(self, gap: float = 0.8) -> None:
        """关一下再开（等价 App 里连点两次电源），用于触发零冷水。

        注意：RF 电源帧是 toggle 语义，因此本操作假设起始状态为“开”，
        连点两次后仍为“开”。起始为关时会变成关——需要状态判断时请先用
        is_on() / App 确认。
        """
        self.toggle(gap)
        self.toggle(gap)

    def ensure_on(self, tries: int = 4) -> bool:
        """反复 toggle 直到能收到状态推送（开机时设备会周期推送），返回是否成功。"""
        for i in range(tries):
            if self.is_on(6.0):
                return True
            self.toggle(1.0)
            time.sleep(1.0)
        return self.is_on(6.0)

    def collect_frames(self, seconds: float = 4.0) -> list:
        try:
            self._send(0xF4, bytes.fromhex("0801000000") + bytes.fromhex("01000100010000"))
        except (socket.timeout, TimeoutError):
            pass
        end = time.time() + seconds
        out = []
        while time.time() < end:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if len(data) >= 16 and data[13:15] == b"\xf4\x00" and data[15] >= 0x3d:
                out.append(data[16:].hex())
        return out

    def detail_raw(self) -> dict:
        """设备信息查询（f4 08 03）：返回原始字节 + 能确认的字段。

        已确认（对比 App 详情页）：服务器域名、MAC 出现在应答里；
        IP/WiFi/运行时长/已连手机数 不在该应答中。
        """
        rsp = self._send(0xF4, bytes.fromhex(
            "0803000000" "01000700" "02000000" "01000300"
            "0c000000" "01000300" "640000"))
        payload = rsp[16:]
        info = {"raw": payload.hex()}
        # 服务器域名：最长的可打印 ASCII 串
        import re as _re
        strs = _re.findall(rb"[ -~]{6,}", payload)
        domains = [x for x in strs if b"." in x and b"galaxy" in x or b".com" in x]
        if domains:
            info["server"] = max(domains, key=len).decode("ascii", "replace").strip("\x00")
        idx = payload.find(b"\x00\x2e\x00\x06")
        if idx >= 0 and idx + 10 <= len(payload):
            mac = payload[idx + 4: idx + 10]
            info["mac"] = ":".join("%02x" % b for b in mac)
        return info

    # ---------------------------------------------------------------- 控制
    def _control(self, rf: bytes) -> bytes:
        payload = (
            bytes.fromhex("0901000000")
            + bytes.fromhex("02000b00")
            + bytes.fromhex("02001000")
            + bytes.fromhex("01000c")
            + rf
        )
        try:
            return self._send(0xF4, payload)
        except (socket.timeout, TimeoutError):
            # 设备有时不回 ACK（尤其关机瞬间），命令通常仍然生效
            return b""

    def set_power(self, on: bool, wait: float = 2.0) -> None:
        """开机用 RF cmd 0x0008，关机用 0x0009（均已实测）。"""
        self._control(rf_frame(0x0008 if on else 0x0009))
        time.sleep(wait)

    def power_off(self, wait: float = 2.0) -> None:
        self.set_power(False, wait)

    def power_on(self, wait: float = 3.0) -> None:
        self.set_power(True, wait)

    def cycle(self, off_wait: float = 1.0, on_wait: float = 1.0) -> None:
        """关一次 -> 开一次，最终保证为开（零冷水触发）。

        实测：关机后要在 1~2 秒内发开机命令（和 App 双击电源一致），
        拖到 5 秒设备会进入深睡而忽略开机。开机命令重复一次兜底。
        """
        self.power_off(off_wait)
        self.power_on(on_wait)
        self.power_on(1.0)

    def is_on(self, wait: float = 10.0) -> bool:
        """best-effort：开机时设备会周期推送 77B 帧，关机后停止。"""
        return len(self.collect_frames(wait)) > 0

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None


def parse_tlvs(payload: bytes) -> dict:
    """解析 f4 08 03 的 TLV（id u16, len u16, value）。"""
    out = {}
    i = 5 if payload[:2] == b"\x08\x03" else 0
    while i + 4 <= len(payload):
        tid = struct.unpack("<H", payload[i:i+2])[0]
        ln = struct.unpack("<H", payload[i+2:i+4])[0]
        if i + 4 + ln > len(payload):
            break
        val = payload[i+4:i+4+ln]
        names = {0x0001: "nickname", 0x000B: "server", 0x002E: "mac"}
        key = names.get(tid, "0x%04x" % tid)
        if tid in (0x0001, 0x000B):
            out[key] = val.rstrip(b"\x00").decode("utf-8", "replace")
        elif tid == 0x002E:
            out[key] = ":".join("%02x" % b for b in val)
        else:
            out[key] = val.hex()
        i += 4 + ln
    return out


# ------------------------------------------------------------------ 状态解码
def decode_power(frame: Optional[bytes]) -> str:
    """从 RF 帧推断电源状态（待用实测样本校准）。"""
    if not frame or len(frame) < 8:
        return "unknown"
    return "unknown"


def decode_set_temp(frame: Optional[bytes]):
    return None


# ---------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="前锋热水器局域网直连客户端")
    p.add_argument("--host", default=os.environ.get("HEATER_HOST", DEFAULT_HOST))
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--sn", default=DEFAULT_SN, help="设备 SN（缺省读 config.ini，缺失时提示输入）")
    p.add_argument("--pwd", default=None, help="设备密码（缺省读 config.ini / HEATER_PWD，缺失时提示输入）")
    p.add_argument("--timeout", type=float, default=2.0)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pair", help="登录并打印设备信息")
    sub.add_parser("status", help="查询状态")
    sub.add_parser("on", help="开机")
    sub.add_parser("off", help="关机")
    sub.add_parser("cycle", help="关->开，最终保证开机")
    args = p.parse_args(argv)

    sn, pwd = resolve_credentials(args.sn, args.pwd)
    h = Heater(args.host, args.port, int(sn), pwd, args.timeout)
    try:
        info = h.login()
        if args.cmd == "pair":
            print("login ok, session=0x%04x" % h.session)
            print("device info:", info[16:].hex())
            name = info.find(b"chiffo")
            print("nickname found:", name >= 0)
        elif args.cmd == "status":
            print(json.dumps(h.status(), ensure_ascii=False))
        elif args.cmd == "on":
            h.power_on(); print("power_on sent")
        elif args.cmd == "off":
            h.power_off(); print("power_off sent")
        elif args.cmd == "cycle":
            h.cycle(); print("cycle done (off -> on)")
        return 0
    except (HeaterError, ValueError, socket.timeout, OSError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1
    finally:
        h.close()


if __name__ == "__main__":
    raise SystemExit(main())
