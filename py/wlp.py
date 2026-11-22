"""WLP v1 —— 自研蓝牙水控器协议参考实现（纯 Python，无第三方依赖）。

包含三部分：
  * 帧编解码（A5 5A / CRC16-CCITT / 可选 4 字节 HMAC 尾）
  * Device  —— 设备侧状态机（阀、计量、超时、退避）
  * Client  —— 手机侧状态机（认证、开阀、心跳、结算）

规范见 ../自研蓝牙热水器方案.md 第 4 节。
端到端测试见 test_wlp.py。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
MAGIC = b"\xA5\x5A"
VER = 0x01
HEADER_LEN = 8
MAC_LEN = 4
CRC_LEN = 2
MAX_PAYLOAD = 512

TYPE_REQ = 0x01
TYPE_RSP = 0x02
TYPE_EVT = 0x03
TYPE_ERR = 0x04
TYPE_SECURED = 0x80

CMD_HELLO = 0x01
CMD_HELLO_RSP = 0x81
CMD_AUTH_BEGIN = 0x02
CMD_AUTH_CHALLENGE = 0x82
CMD_AUTH_FINISH = 0x03
CMD_AUTH_OK = 0x83
CMD_AUTH_ABORT = 0x04

CMD_OPEN = 0x10
CMD_OPEN_ACK = 0x90
CMD_CLOSE = 0x11
CMD_CLOSE_ACK = 0x91
CMD_BEAT = 0x12
CMD_BEAT_ACK = 0x92
CMD_STATUS = 0x20
CMD_STATUS_RSP = 0xA0
CMD_SET_CFG = 0x21
CMD_SET_CFG_ACK = 0xA1
CMD_LOG = 0x30
CMD_LOG_RSP = 0xB0

EVT_SESSION_ENDED = 0xE1
EVT_FAULT = 0xE2
EVT_TICK = 0xE5

ERR_BAD_FRAME = 0x01
ERR_BAD_CRC = 0x02
ERR_BAD_STATE = 0x03
ERR_AUTH_REQUIRED = 0x04
ERR_AUTH_FAILED = 0x05
ERR_REPLAY = 0x06
ERR_LIMIT = 0x07
ERR_BUSY = 0x08
ERR_UNKNOWN_CMD = 0x09
ERR_LOCKED_OUT = 0x0A

STATE_IDLE = 0
STATE_LINKED = 1
STATE_READY = 2
STATE_FLOWING = 3
STATE_CLOSING = 4

STATE_NAMES = {
    STATE_IDLE: "IDLE",
    STATE_LINKED: "LINKED",
    STATE_READY: "READY",
    STATE_FLOWING: "FLOWING",
    STATE_CLOSING: "CLOSING",
}


class ProtocolError(Exception):
    pass


# --------------------------------------------------------------------------- #
# 基础算法
# --------------------------------------------------------------------------- #
def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, 不反转, xorout 0。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Extract + HKDF-Expand。"""
    prk = hmac_sha256(salt, ikm)
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def derive_session_key(psk: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hkdf_sha256(psk, cnonce + dnonce, b"WLP1-SESSION", 32)


def auth_mac_client(psk: bytes, device_id: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hmac_sha256(psk, b"WLP1-AUTH" + device_id + cnonce + dnonce)[:16]


def auth_mac_device(psk: bytes, device_id: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hmac_sha256(psk, b"WLP1-ACK" + device_id + dnonce + cnonce)[:16]


# --------------------------------------------------------------------------- #
# 配对串
# --------------------------------------------------------------------------- #
def make_pairing_string(device_id: bytes, psk: bytes) -> str:
    assert len(device_id) == 8 and len(psk) == 32
    return f"WLP1-{device_id.hex().upper()}-{base64.b32encode(psk).decode().rstrip('=')}"


def parse_pairing_string(text: str) -> tuple[bytes, bytes]:
    parts = text.strip().split("-")
    if len(parts) != 3 or parts[0].upper() != "WLP1":
        raise ValueError("配对串格式应为 WLP1-<16位hex>-<52位base32>")
    device_id = bytes.fromhex(parts[1])
    raw = parts[2].upper()
    raw += "=" * ((8 - len(raw) % 8) % 8)
    psk = base64.b32decode(raw)
    if len(device_id) != 8 or len(psk) != 32:
        raise ValueError("配对串长度不对")
    return device_id, psk


# --------------------------------------------------------------------------- #
# 帧
# --------------------------------------------------------------------------- #
@dataclass
class Frame:
    type: int
    seq: int
    cmd: int
    payload: bytes
    raw: bytes = b""

    @property
    def secured(self) -> bool:
        return bool(self.type & TYPE_SECURED)

    @property
    def base_type(self) -> int:
        return self.type & 0x7F


def build_frame(type_: int, seq: int, cmd: int, payload: bytes = b"", session_key: bytes | None = None) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload 太长")
    secured = session_key is not None
    typ = type_ | (TYPE_SECURED if secured else 0)
    body = MAGIC + bytes([VER, typ]) + struct.pack("<H", len(payload)) + bytes([seq & 0xFF, cmd]) + payload
    if secured:
        body += hmac_sha256(session_key, body)[:MAC_LEN]
    return body + struct.pack("<H", crc16_ccitt(body))


class FrameParser:
    """流式重组：丢字节、粘包、半包都能处理。"""

    def __init__(self, session_key: bytes | None = None):
        self.buf = bytearray()
        self.session_key = session_key
        self.frames: list[Frame] = []
        self.errors: list[str] = []

    def feed(self, data: bytes) -> list[Frame]:
        self.buf += data
        while True:
            idx = self.buf.find(MAGIC)
            if idx < 0:
                if len(self.buf) > 1:
                    del self.buf[:-1]
                break
            if idx:
                del self.buf[:idx]
            if len(self.buf) < HEADER_LEN:
                break

            typ = self.buf[3]
            length = self.buf[4] | (self.buf[5] << 8)
            if length > MAX_PAYLOAD:
                self.errors.append("payload 长度越界")
                del self.buf[0]
                continue

            total = HEADER_LEN + length + (MAC_LEN if typ & TYPE_SECURED else 0) + CRC_LEN
            if len(self.buf) < total:
                break

            raw = bytes(self.buf[:total])
            want = struct.unpack("<H", raw[-2:])[0]
            got = crc16_ccitt(raw[:-2])
            if got != want:
                self.errors.append(f"CRC 错 {got:04x}!={want:04x}")
                del self.buf[0]
                continue

            payload = raw[HEADER_LEN : HEADER_LEN + length]
            if typ & TYPE_SECURED:
                mac_off = HEADER_LEN + length
                if self.session_key is None:
                    self.errors.append("收到加密帧但还没有会话密钥")
                    del self.buf[:total]
                    continue
                want_mac = raw[mac_off : mac_off + MAC_LEN]
                got_mac = hmac_sha256(self.session_key, raw[:mac_off])[:MAC_LEN]
                if got_mac != want_mac:
                    self.errors.append("MAC 校验失败")
                    del self.buf[:total]
                    continue

            self.frames.append(Frame(typ, raw[6], raw[7], payload, raw))
            del self.buf[:total]

        out, self.frames = self.frames, []
        return out


# --------------------------------------------------------------------------- #
# 设备侧
# --------------------------------------------------------------------------- #
class Device:
    """WLP v1 设备状态机。时间全部由外部注入（tick/now），便于测试。"""

    def __init__(
        self,
        device_id: bytes,
        psk: bytes,
        *,
        name: str = "WLP-DEV",
        fw: bytes = b"\x00\x01\x00",
        price_cents_per_m3: int = 2500,
        max_session_s: int = 900,
        max_volume_dl: int = 10000,
        pulses_per_liter: float = 450.0,
        heartbeat_timeout_s: int = 30,
        clock=None,
    ):
        if len(device_id) != 8 or len(psk) != 32:
            raise ValueError("device_id 8 字节 / psk 32 字节")
        self.device_id = device_id
        self.psk = psk
        self.name = name
        self.fw = fw
        self.price_cents_per_m3 = price_cents_per_m3
        self.max_session_s = max_session_s
        self.max_volume_dl = max_volume_dl
        self.pulses_per_liter = pulses_per_liter
        self.heartbeat_timeout_s = heartbeat_timeout_s

        self._now = clock or (lambda: 0.0)
        self.now = 0.0

        self.state = STATE_IDLE
        self.valve_open = False
        self.fault = 0
        self.total_volume_dl = 0
        self.log: list[dict] = []

        self.session_key: bytes | None = None
        self.cnonce: bytes | None = None
        self.dnonce: bytes | None = None
        self.dnonce_at = 0.0
        self.last_seq: int | None = None
        self.seq_out = 0
        self.auth_fail_count = 0
        self.lockout_until = 0.0

        self.session: dict | None = None
        self.last_beat = 0.0
        self.last_tick_emit = 0.0
        self.volume_ml_float = 0.0

        self.parser = FrameParser()
        self.events: list[bytes] = []

    # ---- 工具 ---------------------------------------------------------- #
    def _now_(self) -> float:
        return self.now if self._now is None else max(self.now, self._now())

    def _next_seq(self) -> int:
        self.seq_out = (self.seq_out % 255) + 1
        return self.seq_out

    def _reply(self, cmd: int, payload: bytes = b"", secured: bool = True) -> bytes:
        return build_frame(TYPE_RSP, self._next_seq(), cmd, payload, self.session_key if secured else None)

    def _evt(self, cmd: int, payload: bytes) -> None:
        self.events.append(build_frame(TYPE_EVT, self._next_seq(), cmd, payload, self.session_key))

    def _err(self, code: int, detail: int = 0) -> bytes:
        return build_frame(TYPE_ERR, self._next_seq(), CMD_HELLO_RSP, bytes([code, detail]), None)

    # ---- 生命周期 ------------------------------------------------------ #
    def on_connect(self) -> None:
        self.state = STATE_LINKED
        self.session_key = None
        self.cnonce = self.dnonce = None
        self.last_seq = None
        self.parser = FrameParser()

    def on_disconnect(self) -> None:
        if self.state == STATE_FLOWING:
            self._close_session("disconnect")
        self.state = STATE_IDLE
        self.session_key = None
        self.cnonce = self.dnonce = None
        self.last_seq = None
        self.parser = FrameParser()

    def _open_valve(self, open_: bool) -> None:
        self.valve_open = open_

    def _close_session(self, reason: int) -> dict:
        sess = self.session or {}
        self._open_valve(False)
        result = {
            "volume_dl": int(self.volume_ml_float // 100),
            "seconds": int(self.now - sess.get("start", self.now)),
            "cost_cents": self._cost(int(self.volume_ml_float // 100)),
            "reason": reason,
        }
        if self.state == STATE_FLOWING:
            self.log.append(
                {
                    "start": int(sess.get("start", 0)),
                    "seconds": result["seconds"],
                    "volume_dl": result["volume_dl"],
                    "cost_cents": result["cost_cents"],
                }
            )
            self.total_volume_dl += result["volume_dl"]
            self._evt(EVT_SESSION_ENDED, struct.pack("<IIIB", result["volume_dl"], result["seconds"], result["cost_cents"], reason))
        self.session = None
        self.state = STATE_READY if self.session_key else STATE_LINKED
        self.volume_ml_float = 0.0
        return result

    def _cost(self, volume_dl: int) -> int:
        return (volume_dl * self.price_cents_per_m3 + 5000) // 10000

    # ---- 主循环 -------------------------------------------------------- #
    def tick(self, dt: float, flow_ml_per_min: float) -> None:
        """推进 dt 秒；flow 为模拟的瞬时流量。"""
        self.now += dt
        if self.state == STATE_FLOWING and self.session:
            self.volume_ml_float += flow_ml_per_min * dt / 60.0
            volume_dl = int(self.volume_ml_float // 100)
            max_dl = self.session["max_dl"]
            if volume_dl >= max_dl:
                self._close_session(3)  # 超量
            elif self.now - self.session["start"] >= self.session["max_s"]:
                self._close_session(2)  # 超时
            elif self.now - self.last_beat >= self.heartbeat_timeout_s:
                self._close_session(4)  # 心跳丢失
            elif self.now - self.last_tick_emit >= 1.0:
                self.last_tick_emit = self.now
                self._evt(
                    EVT_TICK,
                    struct.pack("<HIHB", int(flow_ml_per_min), volume_dl, self._temp_out_x10(), self.state),
                )

    def _temp_out_x10(self) -> int:
        return 0

    def handle(self, data: bytes) -> list[bytes]:
        """喂入手机发来的字节流，返回要发回去的帧（含事件）。"""
        self.events = []
        out: list[bytes] = []
        for frame in self.parser.feed(data):
            out.extend(self._handle_frame(frame))
        out.extend(self.events)
        return out

    def _handle_frame(self, f: Frame) -> list[bytes]:
        # HELLO / AUTH 是明文；其余必须加密 + 认证
        if f.cmd == CMD_HELLO:
            payload = self.device_id + self.fw + struct.pack("<HH", 0x0003, 244) + bytes([len(self.name)]) + self.name.encode()
            return [self._reply(CMD_HELLO_RSP, payload, secured=False)]

        if f.cmd == CMD_AUTH_BEGIN:
            if self.now < self.lockout_until:
                return [self._err(ERR_LOCKED_OUT)]
            if len(f.payload) != 16:
                return [self._err(ERR_BAD_FRAME)]
            self.cnonce = bytes(f.payload)
            self.dnonce = os.urandom(16)
            self.dnonce_at = self.now
            self.last_seq = None
            return [self._reply(CMD_AUTH_CHALLENGE, self.dnonce, secured=False)]

        if f.cmd == CMD_AUTH_FINISH:
            if self.dnonce is None or self.cnonce is None:
                return [self._err(ERR_BAD_STATE)]
            if self.now - self.dnonce_at > 60.0:
                return [self._err(ERR_REPLAY)]
            want = auth_mac_client(self.psk, self.device_id, self.cnonce, self.dnonce)
            if not hmac.compare_digest(bytes(f.payload[:16]), want):
                self.auth_fail_count += 1
                backoff = min(300.0, 2.0 ** (self.auth_fail_count - 1))
                self.lockout_until = self.now + backoff
                return [self._err(ERR_AUTH_FAILED, self.auth_fail_count)]
            dnonce = self.dnonce
            self.session_key = derive_session_key(self.psk, self.cnonce, dnonce)
            self.parser.session_key = self.session_key
            self.auth_fail_count = 0
            self.state = STATE_READY
            self.dnonce = None
            mac_s = auth_mac_device(self.psk, self.device_id, self.cnonce, dnonce)
            return [self._reply(CMD_AUTH_OK, mac_s + struct.pack("<H", 1), secured=False)]

        # 以下命令都必须先认证
        if self.session_key is None or not f.secured:
            return [self._err(ERR_AUTH_REQUIRED)]

        if self.last_seq is not None:
            delta = (f.seq - self.last_seq) & 0xFF
            if not (1 <= delta <= 127):
                return [self._err(ERR_REPLAY)]
        self.last_seq = f.seq

        if f.cmd == CMD_OPEN:
            if self.state != STATE_READY:
                return [self._err(ERR_BAD_STATE)]
            if len(f.payload) < 11:
                return [self._err(ERR_BAD_FRAME)]
            max_s, max_dl = struct.unpack("<II", f.payload[:8])
            max_s = min(max_s or self.max_session_s, self.max_session_s)
            max_dl = min(max_dl or self.max_volume_dl, self.max_volume_dl)
            self.session = {"max_s": max_s, "max_dl": max_dl, "start": self.now}
            self.last_beat = self.now
            self.last_tick_emit = self.now
            self.volume_ml_float = 0.0
            self.fault = 0
            self._open_valve(True)
            self.state = STATE_FLOWING
            return [self._reply(CMD_OPEN_ACK, struct.pack("<III", 1, max_s, max_dl))]

        if f.cmd == CMD_CLOSE:
            if self.state != STATE_FLOWING:
                return [self._err(ERR_BAD_STATE)]
            r = self._close_session(1)
            out = [self._reply(CMD_CLOSE_ACK, struct.pack("<IIIB", r["volume_dl"], r["seconds"], r["cost_cents"], r["reason"]))]
            out.extend(self.events)
            self.events = []
            return out

        if f.cmd == CMD_BEAT:
            if self.state != STATE_FLOWING:
                return [self._err(ERR_BAD_STATE)]
            self.last_beat = self.now
            volume_dl = int(self.volume_ml_float // 100)
            return [self._reply(CMD_BEAT_ACK, struct.pack("<BHI", self.state, 0, volume_dl))]

        if f.cmd == CMD_STATUS:
            payload = struct.pack(
                "<BBHIhhhI",
                self.state,
                1 if self.valve_open else 0,
                0,
                self.total_volume_dl + int(self.volume_ml_float // 100),
                0,
                0,
                self.fault,
                int(self.now),
            )
            return [self._reply(CMD_STATUS_RSP, payload)]

        if f.cmd == CMD_SET_CFG:
            if len(f.payload) >= 12:
                price, temp_max, max_s, ppl = struct.unpack("<IhIH", f.payload[:12])
                self.price_cents_per_m3 = price
                self.max_session_s = max_s
                self.pulses_per_liter = float(ppl)
            return [self._reply(CMD_SET_CFG_ACK)]

        if f.cmd == CMD_LOG:
            idx = f.payload[0] if f.payload else 0
            total = len(self.log)
            if 0 <= idx < total:
                e = self.log[total - 1 - idx]
                return [
                    self._reply(
                        CMD_LOG_RSP,
                        struct.pack("<BBIIII", idx, total, e["start"], e["seconds"], e["volume_dl"], e["cost_cents"]),
                    )
                ]
            return [self._reply(CMD_LOG_RSP, struct.pack("<BBIIII", idx, total, 0, 0, 0, 0))]

        return [self._err(ERR_UNKNOWN_CMD, f.cmd)]


# --------------------------------------------------------------------------- #
# 手机侧
# --------------------------------------------------------------------------- #
class Client:
    """WLP v1 客户端状态机。feed() 返回接下来要发给设备的帧。"""

    def __init__(self, device_id: bytes, psk: bytes):
        self.device_id = device_id
        self.psk = psk
        self.seq = 0
        self.session_key: bytes | None = None
        self.cnonce = os.urandom(16)
        self.dnonce: bytes | None = None
        self.parser = FrameParser()
        self.state = "NEW"
        self.response: dict = {}
        self.error: tuple[int, int] | None = None
        self.hello_info: dict = {}
        self.pending: dict | None = None
        self.session_id = 0

    def _seq(self) -> int:
        self.seq = (self.seq % 255) + 1
        return self.seq

    def _sec(self) -> bytes | None:
        return self.session_key

    def hello(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_HELLO, bytes([VER]))]

    def request_open(self, max_s: int = 600, max_dl: int = 5000, temp_target_x10: int = 400, flags: int = 0) -> None:
        self.pending = {"max_s": max_s, "max_dl": max_dl, "temp": temp_target_x10, "flags": flags}

    def feed(self, data: bytes) -> list[bytes]:
        out: list[bytes] = []
        for f in self.parser.feed(data):
            out.extend(self._handle(f))
        return out

    def _handle(self, f: Frame) -> list[bytes]:
        if f.base_type == TYPE_ERR:
            self.error = (f.payload[0], f.payload[1] if len(f.payload) > 1 else 0)
            self.state = "ERROR"
            return []

        if f.cmd == CMD_HELLO_RSP:
            self.hello_info = {
                "device_id": f.payload[:8],
                "fw": f.payload[8:11],
                "caps": struct.unpack("<H", f.payload[11:13])[0],
            }
            if self.hello_info["device_id"] != self.device_id:
                raise ProtocolError("设备 ID 不匹配")
            self.state = "HELLO"
            return [build_frame(TYPE_REQ, self._seq(), CMD_AUTH_BEGIN, self.cnonce)]

        if f.cmd == CMD_AUTH_CHALLENGE:
            self.dnonce = bytes(f.payload[:16])
            mac = auth_mac_client(self.psk, self.device_id, self.cnonce, self.dnonce)
            self.state = "AUTH_SENT"
            return [build_frame(TYPE_REQ, self._seq(), CMD_AUTH_FINISH, mac)]

        if f.cmd == CMD_AUTH_OK:
            mac_s = bytes(f.payload[:16])
            want = auth_mac_device(self.psk, self.device_id, self.cnonce, self.dnonce or b"")
            if not hmac.compare_digest(mac_s, want):
                raise ProtocolError("设备认证失败（mac_s 不对）")
            self.session_key = derive_session_key(self.psk, self.cnonce, self.dnonce)
            self.parser.session_key = self.session_key
            self.state = "READY"
            if self.pending:
                p = self.pending
                self.pending = None
                self.state = "OPENING"
                return [
                    build_frame(
                        TYPE_REQ,
                        self._seq(),
                        CMD_OPEN,
                        struct.pack("<IIhB", p["max_s"], p["max_dl"], p["temp"], p["flags"]),
                        self._sec(),
                    )
                ]
            return []

        if f.cmd == CMD_OPEN_ACK:
            self.session_id, granted_s, granted_dl = struct.unpack("<III", f.payload[:12])
            self.response["granted_s"] = granted_s
            self.response["granted_dl"] = granted_dl
            self.state = "FLOWING"
            return []

        if f.cmd == CMD_CLOSE_ACK:
            volume_dl, seconds, cost, reason = struct.unpack("<IIIB", f.payload[:13])
            self.response.update(volume_dl=volume_dl, seconds=seconds, cost_cents=cost, reason=reason)
            self.state = "READY"
            return []

        if f.cmd == CMD_BEAT_ACK:
            self.state_val, self.flow, self.volume_dl = struct.unpack("<BHI", f.payload[:7])
            return []

        if f.cmd == CMD_STATUS_RSP:
            self.response["status"] = f.payload
            return []

        if f.cmd == EVT_SESSION_ENDED:
            volume_dl, seconds, cost, reason = struct.unpack("<IIIB", f.payload[:13])
            self.response.update(volume_dl=volume_dl, seconds=seconds, cost_cents=cost, reason=reason)
            self.state = "READY"
            return []

        return []

    # ---- 便捷动作 ------------------------------------------------------ #
    def open(self) -> list[bytes]:
        if self.state != "READY":
            raise ProtocolError(f"当前状态 {self.state} 不能开阀")
        p = self.pending or {"max_s": 600, "max_dl": 5000, "temp": 400, "flags": 0}
        self.pending = None
        self.state = "OPENING"
        return [build_frame(TYPE_REQ, self._seq(), CMD_OPEN, struct.pack("<IIhB", p["max_s"], p["max_dl"], p["temp"], p["flags"]), self._sec())]

    def close(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_CLOSE, b"", self._sec())]

    def beat(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_BEAT, b"", self._sec())]

    def status(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_STATUS, b"", self._sec())]


# --------------------------------------------------------------------------- #
# 测试用的直连链路
# --------------------------------------------------------------------------- #
class Link:
    """把 Client 和 Device 直连，自动推进握手，方便没有 BLE 也能跑端到端。"""

    def __init__(self, device: Device, client: Client):
        self.device = device
        self.client = client

    def pump(self, frames: list[bytes]) -> list[bytes]:
        for _ in range(20):
            if not frames:
                break
            blob = b"".join(frames)
            frames = self.client.feed(b"".join(self.device.handle(blob)))
        return frames

    def handshake(self) -> None:
        self.device.on_connect()
        frames = self.client.hello()
        for _ in range(10):
            blob = b"".join(frames)
            replies = self.device.handle(blob)
            frames = self.client.feed(b"".join(replies))
            if not frames:
                break
        if self.client.state != "READY":
            raise ProtocolError(f"握手失败: {self.client.state} {self.client.error}")
