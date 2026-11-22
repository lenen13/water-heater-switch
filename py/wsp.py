"""WSP v1 —— 蓝牙热水器开关协议参考实现。

复用 wlp.py 里已经验证过的帧层（A5 5A / CRC16-CCITT / 4 字节 HMAC 尾），
只把"命令"换成一个开关该有的东西：

    HELLO → AUTH_BEGIN → AUTH_CHALLENGE → AUTH_FINISH → AUTH_OK
    SET_POWER(on/off, 时长)   SET_TIMER(秒)   GET_STATUS   SET_CFG

设备端的硬性安全：到点自动断电、超温自动断电、上电默认断电、
任何情况下"断电"都只是把继电器置为 OFF（失效安全）。
"""

from __future__ import annotations

import base64
import hmac
import os
import struct
from dataclasses import dataclass

from wlp import (
    TYPE_ERR,
    TYPE_EVT,
    TYPE_REQ,
    TYPE_RSP,
    Frame,
    FrameParser,
    build_frame,
    hkdf_sha256,
    hmac_sha256,
)

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
PAIR_PREFIX = "WSP1"

SERVICE_UUID = "57535031-0001-4b1e-9d3a-0c0ffee0beef"
CMD_UUID = "57535031-0002-4b1e-9d3a-0c0ffee0beef"
EVT_UUID = "57535031-0003-4b1e-9d3a-0c0ffee0beef"
DEVICE_PREFIX = "WSP-"

CMD_HELLO = 0x01
CMD_HELLO_RSP = 0x81
CMD_AUTH_BEGIN = 0x02
CMD_AUTH_CHALLENGE = 0x82
CMD_AUTH_FINISH = 0x03
CMD_AUTH_OK = 0x83
CMD_PAIR = 0x04          # 首次配对：手机把随机生成的 32 字节 PSK 交给设备（仅未绑定时可用）
CMD_PAIR_OK = 0x84       # 设备回 device_id，表示已记住
CAPS_BOUND = 0x8000      # HELLO_RSP 的 caps 最高位：1 = 已经绑过手机

CMD_SET_POWER = 0x10
CMD_POWER_ACK = 0x90
CMD_SET_TIMER = 0x11
CMD_TIMER_ACK = 0x91
CMD_GET_STATUS = 0x20
CMD_STATUS_RSP = 0xA0
CMD_SET_CFG = 0x21
CMD_CFG_ACK = 0xA1

EVT_POWER = 0xE1
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

# 断电原因
REASON_MANUAL = 1
REASON_TIMER = 2
REASON_OVERHEAT = 3
REASON_BUTTON = 4
REASON_SAFEBOOT = 5

REASON_TEXT = {
    1: "手动关闭",
    2: "定时到点",
    3: "超温保护",
    4: "按键关闭",
    5: "上电默认关闭",
}


# --------------------------------------------------------------------------- #
# 配对串（WSP1-<16hex>-<52 base32>）
# --------------------------------------------------------------------------- #
def make_pairing(device_id: bytes, psk: bytes) -> str:
    assert len(device_id) == 8 and len(psk) == 32
    return f"{PAIR_PREFIX}-{device_id.hex().upper()}-{base64.b32encode(psk).decode().rstrip('=')}"


def parse_pairing(text: str) -> tuple[bytes, bytes]:
    parts = text.strip().split("-")
    if len(parts) != 3 or parts[0].upper() != PAIR_PREFIX:
        raise ValueError(f"配对串格式应为 {PAIR_PREFIX}-<16位hex>-<52位base32>")
    device_id = bytes.fromhex(parts[1])
    raw = parts[2].upper()
    raw += "=" * ((8 - len(raw) % 8) % 8)
    psk = base64.b32decode(raw)
    if len(device_id) != 8 or len(psk) != 32:
        raise ValueError("配对串长度不对")
    return device_id, psk


def auth_mac_client(psk: bytes, device_id: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hmac_sha256(psk, b"WSP1-AUTH" + device_id + cnonce + dnonce)[:16]


def auth_mac_device(psk: bytes, device_id: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hmac_sha256(psk, b"WSP1-ACK" + device_id + dnonce + cnonce)[:16]


def derive_session_key(psk: bytes, cnonce: bytes, dnonce: bytes) -> bytes:
    return hkdf_sha256(psk, cnonce + dnonce, b"WSP1-SESSION", 32)


# --------------------------------------------------------------------------- #
# 设备侧
# --------------------------------------------------------------------------- #
class Device:
    def __init__(
        self,
        device_id: bytes,
        psk: bytes | None = None,
        *,
        name: str = "WSP-DEV",
        max_on_s: int = 3600,
        temp_limit_x10: int = 750,
        nominal_w: int = 2000,
        clock=None,
    ):
        if len(device_id) != 8 or (psk is not None and len(psk) != 32):
            raise ValueError("device_id 8 字节 / psk 32 字节（未绑定时 psk 可为空）")
        self.device_id = device_id
        self.psk = psk
        self.bound = psk is not None
        self.name = name
        self.fw = b"\x00\x01\x00"

        self.max_on_s = max_on_s
        self.temp_limit_x10 = temp_limit_x10
        self.nominal_w = nominal_w

        self.now = 0.0
        self._clock = clock

        self.power = False
        self.remaining_s = 0.0
        self.total_on_s = 0.0
        self.temp_x10 = 250          # 默认 25.0 °C
        self.fault = 0
        self.last_reason = REASON_SAFEBOOT

        self.session_key: bytes | None = None
        self.cnonce: bytes | None = None
        self.dnonce: bytes | None = None
        self.dnonce_at = 0.0
        self.last_seq: int | None = None
        self.seq_out = 0
        self.auth_fails = 0
        self.lockout_until = 0.0

        self.parser = FrameParser()
        self.events: list[bytes] = []
        self.tick_accum = 0.0

    # ---- 基础 ---------------------------------------------------------- #
    def _time(self) -> float:
        return max(self.now, self._clock() if self._clock else 0.0)

    def _next_seq(self) -> int:
        self.seq_out = (self.seq_out % 255) + 1
        return self.seq_out

    def _reply(self, cmd: int, payload: bytes = b"", secured: bool = True) -> bytes:
        return build_frame(TYPE_RSP, self._next_seq(), cmd, payload, self.session_key if secured else None)

    def _evt(self, cmd: int, payload: bytes) -> None:
        self.events.append(build_frame(TYPE_EVT, self._next_seq(), cmd, payload, self.session_key))

    def _err(self, code: int, detail: int = 0) -> bytes:
        return build_frame(TYPE_ERR, self._next_seq(), CMD_HELLO_RSP, bytes([code, detail]), None)

    # ---- 开关动作 ------------------------------------------------------ #
    def _power_payload(self, reason: int) -> bytes:
        return struct.pack("<BIB", 1 if self.power else 0, int(self.remaining_s), reason)

    def set_power(self, on: bool, duration_s: int = 0, reason: int = REASON_MANUAL) -> None:
        if not on:
            self.power = False
            self.remaining_s = 0.0
            self.last_reason = reason
            return
        if self.fault:
            return
        dur = duration_s or self.max_on_s
        self.power = True
        self.remaining_s = float(min(dur, self.max_on_s))
        self.last_reason = 0

    def _force_off(self, reason: int) -> None:
        self.power = False
        self.remaining_s = 0.0
        self.last_reason = reason
        self._evt(EVT_POWER, self._power_payload(reason))

    # ---- 生命周期 ------------------------------------------------------ #
    def on_connect(self) -> None:
        self.session_key = None
        self.cnonce = self.dnonce = None
        self.last_seq = None
        self.parser = FrameParser()

    def on_disconnect(self) -> None:
        # 注意：断开蓝牙不关电，否则"开一会儿"就没意义了；定时器仍在设备上生效
        self.session_key = None
        self.cnonce = self.dnonce = None
        self.last_seq = None
        self.parser = FrameParser()

    def tick(self, dt: float, temp_c: float | None = None) -> None:
        if temp_c is not None:
            self.temp_x10 = int(temp_c * 10)
        self.now += dt
        if not self.power:
            return

        self.remaining_s = max(0.0, self.remaining_s - dt)
        self.total_on_s += dt

        if self.temp_x10 >= self.temp_limit_x10:
            self.fault = 1
            self._evt(EVT_FAULT, bytes([1, max(0, min(255, self.temp_x10 // 10))]))
            self._force_off(REASON_OVERHEAT)
            return

        self.tick_accum += dt
        if self.tick_accum >= 1.0:
            self.tick_accum -= 1.0
            self._evt(
                EVT_TICK,
                struct.pack("<BIH", 1, int(self.remaining_s), self.temp_x10 if self.temp_x10 >= 0 else 0),
            )

        if self.remaining_s <= 0:
            self._force_off(REASON_TIMER)

    # ---- 收帧 ---------------------------------------------------------- #
    def handle(self, data: bytes) -> list[bytes]:
        self.events = []
        out: list[bytes] = []
        for frame in self.parser.feed(data):
            out.extend(self._handle_frame(frame))
        out.extend(self.events)
        return out

    def unbind(self) -> None:
        """解除绑定：下一次任何手机连上来都能重新配对（对应长按设备按键 5 秒）。"""
        self.psk = None
        self.bound = False
        self.session_key = None
        self.cnonce = self.dnonce = None
        self.last_seq = None

    def _handle_frame(self, f: Frame) -> list[bytes]:
        if f.cmd == CMD_HELLO:
            caps = 0x0006 | (CAPS_BOUND if self.bound else 0)
            payload = (
                self.device_id
                + self.fw
                + struct.pack("<HH", caps, 244)
                + bytes([len(self.name)])
                + self.name.encode()
            )
            return [self._reply(CMD_HELLO_RSP, payload, secured=False)]

        # 首次配对：只允许在"还没绑过手机"时执行一次
        if f.cmd == CMD_PAIR:
            if self.bound:
                return [self._err(ERR_BAD_STATE)]
            if len(f.payload) != 32:
                return [self._err(ERR_BAD_FRAME)]
            self.psk = bytes(f.payload)
            self.bound = True
            return [self._reply(CMD_PAIR_OK, self.device_id, secured=False)]

        if f.cmd == CMD_AUTH_BEGIN:
            if not self.bound or self.psk is None:
                return [self._err(ERR_AUTH_FAILED)]
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
            if not self.bound or self.psk is None:
                return [self._err(ERR_AUTH_FAILED)]
            if self.dnonce is None or self.cnonce is None:
                return [self._err(ERR_BAD_STATE)]
            if self.now - self.dnonce_at > 60.0:
                return [self._err(ERR_REPLAY)]
            want = auth_mac_client(self.psk, self.device_id, self.cnonce, self.dnonce)
            if not hmac.compare_digest(bytes(f.payload[:16]), want):
                self.auth_fails += 1
                self.lockout_until = self.now + min(300.0, 2.0 ** (self.auth_fails - 1))
                return [self._err(ERR_AUTH_FAILED, self.auth_fails)]
            dnonce = self.dnonce
            cnonce = self.cnonce
            self.session_key = derive_session_key(self.psk, cnonce, dnonce)
            self.parser.session_key = self.session_key
            self.auth_fails = 0
            mac_s = auth_mac_device(self.psk, self.device_id, cnonce, dnonce)
            self.dnonce = None
            self.cnonce = None
            return [self._reply(CMD_AUTH_OK, mac_s + struct.pack("<H", 1), secured=False)]

        if self.session_key is None or not f.secured:
            return [self._err(ERR_AUTH_REQUIRED)]

        if self.last_seq is not None:
            delta = (f.seq - self.last_seq) & 0xFF
            if not (1 <= delta <= 127):
                return [self._err(ERR_REPLAY)]
        self.last_seq = f.seq

        if f.cmd == CMD_SET_POWER:
            if len(f.payload) < 5:
                return [self._err(ERR_BAD_FRAME)]
            desired = f.payload[0]
            dur = struct.unpack("<I", f.payload[1:5])[0]
            self.set_power(bool(desired), dur)
            return [self._reply(CMD_POWER_ACK, self._power_payload(self.last_reason if not self.power else 0))]

        if f.cmd == CMD_SET_TIMER:
            if len(f.payload) < 4:
                return [self._err(ERR_BAD_FRAME)]
            if not self.power:
                return [self._err(ERR_BAD_STATE)]
            sec = struct.unpack("<I", f.payload[:4])[0]
            self.remaining_s = float(min(max(sec, 1), self.max_on_s))
            return [self._reply(CMD_TIMER_ACK, struct.pack("<I", int(self.remaining_s)))]

        if f.cmd == CMD_GET_STATUS:
            payload = struct.pack(
                "<BIhIIB",
                1 if self.power else 0,
                int(self.remaining_s),
                self.temp_x10,
                int(self.total_on_s),
                self.max_on_s,
                self.fault,
            )
            return [self._reply(CMD_STATUS_RSP, payload)]

        if f.cmd == CMD_SET_CFG:
            if len(f.payload) >= 8:
                max_on, temp_limit, nominal = struct.unpack("<IhH", f.payload[:8])
                self.max_on_s = max(60, min(7200, max_on))
                self.temp_limit_x10 = max(400, min(900, temp_limit))
                self.nominal_w = nominal
                if self.power and self.remaining_s > self.max_on_s:
                    self.remaining_s = float(self.max_on_s)
            return [self._reply(CMD_CFG_ACK)]

        return [self._err(ERR_UNKNOWN_CMD, f.cmd)]


# --------------------------------------------------------------------------- #
# 手机侧
# --------------------------------------------------------------------------- #
class Client:
    """手机侧。

    psk 传 None 表示"这台手机还没存过密钥"：
      - 设备未绑定 → 自动生成密钥并发 PAIR，配对完成后 client.psk 就是新密钥，调用方存起来即可；
      - 设备已绑定 → 不硬闯，状态置 NO_KEY，调用方应提示"长按设备按键重置"。
    """

    def __init__(self, device_id: bytes | None = None, psk: bytes | None = None):
        self.device_id = device_id
        self.psk = psk
        self.seq = 0
        self.session_key: bytes | None = None
        self.cnonce = os.urandom(16)
        self.dnonce: bytes | None = None
        self.parser = FrameParser()
        self.state = "NEW"
        self.error: tuple[int, int] | None = None
        self.info: dict = {}
        self.status: dict = {}
        self.last_event: dict | None = None
        self.just_paired = False

    def _seq(self) -> int:
        self.seq = (self.seq % 255) + 1
        return self.seq

    def hello(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_HELLO, bytes([1]))]

    def power(self, on: bool, duration_s: int = 0) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_SET_POWER, struct.pack("<BI", 1 if on else 0, duration_s), self.session_key)]

    def set_timer(self, sec: int) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_SET_TIMER, struct.pack("<I", sec), self.session_key)]

    def get_status(self) -> list[bytes]:
        return [build_frame(TYPE_REQ, self._seq(), CMD_GET_STATUS, b"", self.session_key)]

    def set_cfg(self, max_on_s: int, temp_limit_x10: int, nominal_w: int) -> list[bytes]:
        return [
            build_frame(
                TYPE_REQ,
                self._seq(),
                CMD_SET_CFG,
                struct.pack("<IhHH", max_on_s, temp_limit_x10, nominal_w, 0),
                self.session_key,
            )
        ]

    def feed(self, data: bytes) -> list[bytes]:
        out: list[bytes] = []
        for f in self.parser.feed(data):
            out.extend(self._handle(f))
        return out

    def _parse_status(self, p: bytes) -> dict:
        on, remaining, temp, total, max_on, fault = struct.unpack("<BIhIIB", p[:16])
        return {
            "on": bool(on),
            "remaining_s": remaining,
            "temp_x10": temp,
            "total_on_s": total,
            "max_on_s": max_on,
            "fault": fault,
        }

    def _handle(self, f: Frame) -> list[bytes]:
        if f.base_type == TYPE_ERR:
            self.error = (f.payload[0], f.payload[1] if len(f.payload) > 1 else 0)
            return []

        if f.cmd == CMD_HELLO_RSP:
            name_len = f.payload[15]
            self.info = {
                "device_id": f.payload[:8],
                "fw": f.payload[8:11],
                "caps": struct.unpack("<H", f.payload[11:13])[0],
                "name": f.payload[16 : 16 + name_len].decode(errors="replace"),
            }
            if self.device_id is None:
                self.device_id = bytes(f.payload[:8])      # 新手机：从设备广播里学 ID
            elif self.info["device_id"] != self.device_id:
                raise ValueError("设备 ID 与配对串不匹配")
            bound = bool(self.info["caps"] & CAPS_BOUND)
            self.info["bound"] = bound
            self.state = "HELLO"
            if not bound:
                # 设备还没绑手机 → 自动配对，不需要用户输入任何东西
                if self.psk is None:
                    self.psk = os.urandom(32)
                self.state = "PAIRING"
                return [build_frame(TYPE_REQ, self._seq(), CMD_PAIR, self.psk)]
            if self.psk is None:
                self.state = "NO_KEY"
                self.error = (ERR_AUTH_FAILED, 0)
                return []
            return [build_frame(TYPE_REQ, self._seq(), CMD_AUTH_BEGIN, self.cnonce)]

        if f.cmd == CMD_PAIR_OK:
            self.just_paired = True
            self.state = "AUTH"
            return [build_frame(TYPE_REQ, self._seq(), CMD_AUTH_BEGIN, self.cnonce)]

        if f.cmd == CMD_AUTH_CHALLENGE:
            self.dnonce = bytes(f.payload[:16])
            mac = auth_mac_client(self.psk, self.device_id, self.cnonce, self.dnonce)
            self.state = "AUTH"
            return [build_frame(TYPE_REQ, self._seq(), CMD_AUTH_FINISH, mac)]

        if f.cmd == CMD_AUTH_OK:
            mac_s = bytes(f.payload[:16])
            want = auth_mac_device(self.psk, self.device_id, self.cnonce, self.dnonce)
            if not hmac.compare_digest(mac_s, want):
                raise ValueError("设备认证失败")
            self.session_key = derive_session_key(self.psk, self.cnonce, self.dnonce)
            self.parser.session_key = self.session_key
            self.state = "READY"
            return []

        if f.base_type == TYPE_EVT:
            if f.cmd == EVT_TICK:
                on, remaining, temp = struct.unpack("<BIH", f.payload[:7])
                self.last_event = {"on": bool(on), "remaining_s": remaining, "temp_x10": temp}
            elif f.cmd == EVT_POWER:
                on, remaining, reason = struct.unpack("<BIB", f.payload[:6])
                self.last_event = {"on": bool(on), "remaining_s": remaining, "reason": reason}
            return []

        if f.cmd == CMD_POWER_ACK:
            on, remaining, reason = struct.unpack("<BIB", f.payload[:6])
            self.status.update(on=bool(on), remaining_s=remaining)
            return []

        if f.cmd == CMD_TIMER_ACK:
            self.status["remaining_s"] = struct.unpack("<I", f.payload[:4])[0]
            return []

        if f.cmd == CMD_STATUS_RSP:
            self.status.update(self._parse_status(f.payload))
            return []

        return []


class Link:
    def __init__(self, device: Device, client: Client):
        self.device = device
        self.client = client

    def pump(self, frames: list[bytes]) -> list[bytes]:
        for _ in range(12):
            if not frames:
                break
            frames = self.client.feed(b"".join(self.device.handle(b"".join(frames))))
        return frames

    def handshake(self) -> None:
        self.device.on_connect()
        frames = self.client.hello()
        for _ in range(8):
            replies = self.device.handle(b"".join(frames))
            frames = self.client.feed(b"".join(replies))
            if not frames:
                break
        if self.client.state != "READY":
            raise RuntimeError(f"握手失败: {self.client.state} {self.client.error}")
