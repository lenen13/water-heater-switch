"""waterctl（蓝牙水控器）协议参考实现 —— 纯 Python，零第三方依赖。

只用于学习、互通测试、以及自研设备的参考实现。
逐字节协议说明见上一级目录的《水控器协议解构.md》。

原始实现: https://github.com/celesWuff/waterctl  (MIT, branch 2.x)

本文件复刻了这些原始部件:
  * src/algorithms.ts  crc16changgong / crc16cgaeaf
  * src/utils.ts       decAsHex (BCD)
  * src/deputy.wat     makeKey(a,b,c,d)，用查表替代 WASM
  * src/solvers.ts     makeStartEpilogue / makeUnlockResponse
"""

from __future__ import annotations

import datetime as _dt
import random as _random
from pathlib import Path
from typing import Iterable, Sequence

# --------------------------------------------------------------------------- #
# GATT 层
# --------------------------------------------------------------------------- #
SERVICE_F1F0 = "0000f1f0-0000-1000-8000-00805f9b34fb"
CHAR_F1F1_TXD = "0000f1f1-0000-1000-8000-00805f9b34fb"  # 手机 -> 设备, Write / WriteWithoutResponse
CHAR_F1F2_RXD = "0000f1f2-0000-1000-8000-00805f9b34fb"  # 设备 -> 手机, Notify

# --------------------------------------------------------------------------- #
# 帧常量
# --------------------------------------------------------------------------- #
HOST_HDR = b"\xFE\xFE"  # 手机 -> 设备
DEV_HDR = b"\xFD\xFD"  # 设备 -> 手机
MAGIC = 0x09  # 固定第三字节
FRAME_LEN = 20  # 绝大多数命令是 20 字节，正好塞满 ATT MTU 23 的负载

# 固定负载（src/payloads.ts）
START_PROLOGUE = b"\xFE\xFE\x09\xB0\x01\x01\x00\x00"
END_PROLOGUE = b"\xFE\xFE\x09\xB3\x00\x00"
END_EPILOGUE = b"\xFE\xFE\x09\xB4\x00\x00"
OFFLINE_BOMB_FIX = b"\xFE\xFE\x09\xBC\x00\x00"
BA_ACK = b"\xFE\xFE\x09\xBA\x00\x00"

COMMAND_NAMES = {
    0xB0: "START_REQ        手机->设备 开始会话",
    0xB1: "START_RSP        设备->手机 旧固件状态/应答",
    0xB2: "START_EPILOGUE   手机->设备 会话参数 / 设备回显开门",
    0xB3: "END_REQ / END_RSP 结束会话 + 本次用量",
    0xB4: "END_EPILOGUE     手机->设备 收尾",
    0xAE: "AUTH_REQ         设备->手机 挑战",
    0xAF: "AUTH_RSP         手机->设备 应答 / 设备->手机 结果",
    0xBA: "SEND_USER_INFO   设备->手机 要求上传用户信息",
    0xBC: "OFFLINE_FIX      手机->设备 清除残留的离线会话",
    0xC8: "REFUSED          设备->手机 拒绝启动",
    0xAA: "TELEMETRY        设备->手机 遥测/心跳",
    0xB5: "SET_TEMP         设备->手机 温度设置",
    0xB8: "UNKNOWN_B8       设备->手机 未知",
}

# --------------------------------------------------------------------------- #
# deputy 查找表
# --------------------------------------------------------------------------- #
_TABLE_FILE = Path(__file__).with_name("deputy_table.bin")
_TABLE = _TABLE_FILE.read_bytes()
if len(_TABLE) != 2096:
    raise RuntimeError(f"deputy_table.bin 长度异常: {len(_TABLE)}")

# WASM 模块只有一页 (64 KiB) 线性内存，data 段覆盖 0..2095，其余读出来恒为 0。
# makeKey 里的下标可能越过 2095（例如 1938+ia），所以这里补零模拟整页内存。
_MEM = _TABLE + bytes(65536 - len(_TABLE))


def _t(offset: int) -> int:
    """等价于 WAT 里的 i32.load8_u。"""
    return _MEM[offset & 0xFFFF]


# --------------------------------------------------------------------------- #
# 校验 / 编码
# --------------------------------------------------------------------------- #
def crc16_changgong(text: str) -> int:
    """B2 帧用的 CRC16。

    width=16 poly=0x8005 init=0xe808 refin/refout=true xorout=0
    （代码里写的是反射形式 init=0x1017、poly=0xA001）
    """
    crc = 0x1017
    for byte in text.encode("ascii"):
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def crc16_cgaeaf(data: Sequence[int]) -> int:
    """AF 帧用的校验：同样跑一遍 CRC16，但只保留低 8 位并 xor 0x75。

    width=16 poly=0x8005 init=0xf856 refin/refout=true xorout=0x0075
    """
    crc = 0x6A1F
    for byte in data:
        crc ^= byte & 0xFF
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return (crc ^ 0x75) & 0xFF


def dec_as_hex(value: int) -> int:
    """十进制 -> BCD。42 -> 0x42，2021 -> 0x2021（超过一字节时由调用方截断）。"""
    if value <= 0:
        return 0
    return (value % 10) | (dec_as_hex(value // 10) << 4)


# --------------------------------------------------------------------------- #
# 核心: 认证应答里的 4 字节 key
# --------------------------------------------------------------------------- #
def make_key(a: int, b: int, c: int, d: int) -> bytes:
    """deputy.wat 中 makeKey(a,b,c,d) 的等价实现。

    输入是 AE 帧的 [nonceHi, nonceLo, macHi, macLo]，输出 4 字节。
    原始 WASM 把结果写在内存 2096..2099，JS 侧再用 Uint32Array[524] 按
    小端读出后翻转成大端，所以这里直接返回 [T(1938+ia), T(1808+ib), T(2082+ic), T(1952+id)]。
    """
    if b == 0xFF and (a & 1):
        a += 2
    if a == 257:
        a = 0

    ia = d & 7
    high = d & ~7
    for bit in (3, 4, 5, 6, 7):
        if high & (1 << bit):
            ia ^= 4
    ia ^= _t(b)
    for bit, k in enumerate((1, 1, 2, 7, 1, 1, 1, 1)):
        if a & (1 << bit):
            ia ^= k

    ic = c & 7
    high = c & ~7
    for bit in (3, 4, 5, 6, 7):
        if high & (1 << bit):
            ic ^= 4
    ic ^= _t(768 + (b & 15))

    d = _t(256 + b) ^ d
    d = _t(512 + a) ^ d
    ib = _t(1296 + d)

    c = _t(784 + b) ^ c
    c = _t(1040 + a) ^ c
    id_ = _t(1552 + c)

    return bytes((_t(1938 + ia), _t(1808 + ib), _t(2082 + ic), _t(1952 + id_)))


# --------------------------------------------------------------------------- #
# 认证应答 (AE -> AF)
# --------------------------------------------------------------------------- #
def make_unlock_response(request: bytes, device_name: str) -> bytes:
    """把设备的 0xAE 挑战帧算成 20 字节的 0xAF 应答帧。"""
    if len(request) < 10:
        raise ValueError(f"AE 帧太短: {len(request)} 字节")

    unknown = request[5]  # 含义未知，原样回显
    nonce = (request[6] << 8) | request[7]  # 自增计数器，不是随机数
    mac_hi, mac_lo = request[8], request[9]  # MAC 地址最后两字节

    if nonce == 0xFFFF:
        new_nonce = b"\x01\x00"  # 设备 bug: 0xffff 之后不回绕到 0
    else:
        n = nonce + 1
        new_nonce = bytes(((n >> 8) & 0xFF, n & 0xFF))

    raw_key = make_key(request[6], request[7], mac_hi, mac_lo)
    mask = [ord(ch) - 0x30 for ch in device_name[-4:]]  # "Water33982" -> [3,9,8,2]
    key = bytes(x ^ m for x, m in zip(raw_key, mask))

    body = bytes((unknown,)) + new_nonce + key + b"\xFE\x87" + bytes(6)
    return HOST_HDR + b"\x09\xAF" + bytes((crc16_cgaeaf(body),)) + body


# --------------------------------------------------------------------------- #
# 开始会话 (B2)
# --------------------------------------------------------------------------- #
def make_random_user_id(rng: _random.Random | None = None) -> bytes:
    """1..9999 的随机用户号，高低字节各自转 BCD。"""
    rng = rng or _random
    n = rng.randint(1, 9999)
    return bytes((dec_as_hex(n >> 8) & 0xFF, dec_as_hex(n & 0xFF) & 0xFF))


def make_datetime_array(now: _dt.datetime | None = None) -> bytes:
    """[YY, MM, DD, hh, mm, ss] 各转 BCD，年份取后两位。"""
    now = now or _dt.datetime.now()
    values = (now.year % 100, now.month, now.day, now.hour, now.minute, now.second)
    return bytes(dec_as_hex(v) & 0xFF for v in values)


def make_start_epilogue(
    device_name: str,
    key_auth: bool = False,
    user_id: bytes | None = None,
    when: bytes | None = None,
) -> bytes:
    """20 字节 B2 帧：真正开启会话的那一条命令。

    key_auth=True 表示前面已经通过 0xAE/0xAF 认证（新固件），mn 写 0x0B；
    否则写 0xFF（旧固件）。
    """
    checksum = crc16_changgong(device_name[-5:])
    mn = 0x0B if key_auth else 0xFF
    user_id = user_id if user_id is not None else make_random_user_id()
    when = when if when is not None else make_datetime_array()

    return (
        HOST_HDR
        + b"\x09\xB2"
        + bytes((0x01, checksum & 0xFF, (checksum >> 8) & 0xFF, mn, 0x00))
        + user_id
        + when
        + b"\x0F\x27\x00"
    )


def make_start_epilogue_offlinebomb(user_id: bytes | None = None, when: bytes | None = None) -> bytes:
    """已废弃的 0xBB 帧（老漏洞的形态），保留仅供对照与研究。"""
    user_id = user_id if user_id is not None else make_random_user_id()
    when = when if when is not None else make_datetime_array()
    return b"\xFE\xFE\x09\xBB\x01\x01\x0D\x00\x50" + user_id + when + b"\x00\x20\x00"


# --------------------------------------------------------------------------- #
# 收包修补 / 显示
# --------------------------------------------------------------------------- #
def repair_device_frame(raw: bytes) -> bytes | None:
    """修设备固件丢了帧头字节的包。

    实测设备偶尔只发 [FD, 09, ...] 或 [09, ...]，需要补回 FD FD；
    单字节 0xFD 是残包，直接丢弃。返回 None 表示丢弃。
    """
    if not raw:
        return None
    if raw.startswith(DEV_HDR):
        return raw
    if raw == b"\xFD":
        return None
    if raw.startswith(b"\xFD"):
        return b"\xFD" + raw
    if raw.startswith(b"\x09"):
        return DEV_HDR + raw
    return raw


def hexdump(data: Iterable[int]) -> str:
    return " ".join(f"{b:02x}" for b in data)


def command_name(cmd: int) -> str:
    return COMMAND_NAMES.get(cmd, f"UNKNOWN_{cmd:02X}")
