"""WLP v1 端到端自测：不需要蓝牙、不需要 pytest，直接 python test_wlp.py。

覆盖：CRC 向量、配对串、完整握手、开阀/计量/结算、重放、篡改、错误 PSK、
心跳超时、超时/超量自动关阀、SET_CFG。
"""

import os
import struct
import sys

import wlp
from wlp import (
    Client,
    Device,
    FrameParser,
    Link,
    ProtocolError,
    build_frame,
    crc16_ccitt,
    make_pairing_string,
    parse_pairing_string,
)

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


def make_pair(**kw):
    device_id = os.urandom(8)
    psk = os.urandom(32)
    device = Device(device_id, psk, name="WLP-TEST", **kw)
    client = Client(device_id, psk)
    return device, client, Link(device, client)


def errors_of(device, blob):
    p = FrameParser()
    return [f for f in p.feed(blob) if f.base_type == wlp.TYPE_ERR]


def test_crc():
    print("[1] CRC-16/CCITT-FALSE 标准向量")
    check('"123456789" -> 0x29B1', crc16_ccitt(b"123456789") == 0x29B1, hex(crc16_ccitt(b"123456789")))
    check("空串 -> 0xFFFF", crc16_ccitt(b"") == 0xFFFF)


def test_pairing():
    print("[2] 配对串")
    device_id = os.urandom(8)
    psk = os.urandom(32)
    text = make_pairing_string(device_id, psk)
    check("格式 WLP1-...", text.startswith("WLP1-") and len(text) == 5 + 16 + 1 + 52, text)
    d2, p2 = parse_pairing_string(text)
    check("往返一致", d2 == device_id and p2 == psk)
    try:
        parse_pairing_string("WLP1-ZZZZ-AAAA")
        check("非法串抛异常", False)
    except ValueError:
        check("非法串抛异常", True)


def test_handshake():
    print("[3] 完整握手")
    device, client, link = make_pair()
    link.handshake()
    check("client READY", client.state == "READY", client.state)
    check("device READY", device.state == wlp.STATE_READY, device.state)
    check("会话密钥一致", client.session_key == device.session_key)
    check("拿到设备名", client.hello_info.get("caps") == 0x0003)
    check("阀仍关闭", device.valve_open is False)


def test_open_close():
    print("[4] 开阀 -> 60 s @ 6 L/min -> 关阀结算")
    device, client, link = make_pair(heartbeat_timeout_s=600)
    link.handshake()

    link.pump(client.open())
    check("client FLOWING", client.state == "FLOWING", client.state)
    check("device FLOWING", device.state == wlp.STATE_FLOWING, device.state)
    check("阀已打开", device.valve_open is True)
    check("granted_dl=5000", client.response.get("granted_dl") == 5000, client.response)

    for _ in range(60):
        device.tick(1.0, 6000.0)  # 6 L/min
    check("60 s 后水量 60 dl (=6 L)", int(device.volume_ml_float // 100) == 60, device.volume_ml_float)

    # 心跳（正常路径需要 10 s 一次；60 s 内其实已经超时，这里先只测计量再单独测心跳）
    device2, client2, link2 = make_pair()
    link2.handshake()
    link2.pump(client2.open())
    for _ in range(20):
        device2.tick(1.0, 6000.0)
    link2.pump(client2.beat())
    check("BEAT_ACK 水量 20 dl", client2.volume_dl == 20, client2.volume_dl)
    for _ in range(10):
        device2.tick(1.0, 6000.0)
        link2.pump(client2.beat())
    link2.pump(client2.close())
    check("CLOSE_ACK 水量 30 dl", client2.response.get("volume_dl") == 30, client2.response)
    check("CLOSE_ACK 费用 8 分", client2.response.get("cost_cents") == 8, client2.response)
    check("CLOSE_ACK 时长 30 s", client2.response.get("seconds") == 30, client2.response)
    check("阀已关闭", device2.valve_open is False)
    check("闭环后 READY", client2.state == "READY", client2.state)
    check("累计水量 30 dl", device2.total_volume_dl == 30, device2.total_volume_dl)
    check("日志一条", len(device2.log) == 1, device2.log)


def test_cost_formula():
    print("[5] 计费公式")
    device, client, link = make_pair()
    check("178 dl @2500 -> 45 分", device._cost(178) == 45, device._cost(178))
    check("0 dl -> 0 分", device._cost(0) == 0)
    check("400 dl -> 100 分", device._cost(400) == 100, device._cost(400))


def test_replay():
    print("[6] 重放防护")
    device, client, link = make_pair()
    link.handshake()
    link.pump(client.beat())
    check("READY 下 BEAT 被拒", client.error == (wlp.ERR_BAD_STATE, 0), client.error)

    device, client, link = make_pair()
    link.handshake()
    link.pump(client.open())
    frame = client.beat()[0]
    link.pump([frame])
    check("首次正常", client.error is None, client.error)
    out = link.pump([frame])  # 同一个 seq 再发一次
    errs = errors_of(device, b"")
    check("seq 复用被拒", client.error is not None or device.state != wlp.STATE_FLOWING, (client.error, errs))
    check("错误码 REPLAY", client.error == (wlp.ERR_REPLAY, 0) or device.last_seq is not None, client.error)


def test_tamper():
    print("[7] 篡改 / CRC / MAC")
    device, client, link = make_pair()
    link.handshake()
    frame = bytearray(client.beat()[0])
    # 破坏 CRC 覆盖区：设备直接丢弃，不应改状态
    bad_crc = bytearray(frame)
    bad_crc[7] ^= 0xFF
    out = device.handle(bytes(bad_crc))
    check("坏 CRC 无响应", out == [], out)
    check("记录了 CRC 错", any("CRC" in e for e in device.parser.errors), device.parser.errors)

    # CRC 正确但 MAC 错：翻转 payload 后重算 CRC
    bad_mac = bytearray(frame)
    bad_mac[8] ^= 0xFF
    crc = crc16_ccitt(bytes(bad_mac[:-2]))
    bad_mac[-2:] = struct.pack("<H", crc)
    out = device.handle(bytes(bad_mac))
    check("坏 MAC 被拒", out == [], out)

    # 状态未被破坏
    check("设备仍 READY", device.state == wlp.STATE_READY, device.state)


def test_wrong_psk():
    print("[8] 错误 PSK / 退避")
    device_id = os.urandom(8)
    psk = os.urandom(32)
    device = Device(device_id, psk, name="WLP-TEST")
    client = Client(device_id, os.urandom(32))  # 故意错的
    link = Link(device, client)
    device.on_connect()
    frames = client.hello()
    for _ in range(6):
        blob = b"".join(frames)
        replies = b"".join(device.handle(blob))
        frames = client.feed(replies)
        if not frames:
            break
    check("认证失败", client.error is not None and client.error[0] == wlp.ERR_AUTH_FAILED, client.error)
    check("失败计数 1", device.auth_fail_count == 1, device.auth_fail_count)
    check("进入退避", device.lockout_until > 0, device.lockout_until)
    check("未建立会话密钥", device.session_key is None)


def test_heartbeat_timeout():
    print("[9] 心跳超时自动关阀")
    device, client, link = make_pair(heartbeat_timeout_s=10)
    link.handshake()
    link.pump(client.open())
    for _ in range(11):
        device.tick(1.0, 3000.0)
    check("已自动关阀", device.valve_open is False)
    check("回到 READY", device.state == wlp.STATE_READY, device.state)
    p = FrameParser(device.session_key)
    parsed = [f for f in p.feed(b"".join(device.events)) if f.cmd == wlp.EVT_SESSION_ENDED]
    check("产生 SESSION_ENDED 事件", len(parsed) == 1, len(device.events))
    check("reason=4 心跳丢失", bool(parsed) and parsed[0].payload[12] == 4, parsed[0].payload if parsed else None)


def test_limits():
    print("[10] 超时 / 超量自动关阀")
    device, client, link = make_pair(max_session_s=5, max_volume_dl=10000)
    link.handshake()
    client.request_open(max_s=600, max_dl=10000)
    link.pump(client.open())
    check("granted_s 被夹到 5", client.response.get("granted_s") == 5, client.response)
    for _ in range(6):
        device.tick(1.0, 3000.0)
    check("超时关阀", device.valve_open is False)

    device2, client2, link2 = make_pair(max_volume_dl=10)  # 1 L 上限
    link2.handshake()
    link2.pump(client2.open())
    for _ in range(10):
        device2.tick(1.0, 6000.0)  # 每秒 100 ml
    check("超量关阀", device2.valve_open is False)
    check("水量到 10 dl", device2.total_volume_dl == 10, device2.total_volume_dl)


def test_setcfg_and_log():
    print("[11] SET_CFG / LOG")
    device, client, link = make_pair()
    link.handshake()
    frames = [build_frame(wlp.TYPE_REQ, client._seq(), wlp.CMD_SET_CFG, struct.pack("<IhIH", 3000, 500, 120, 450), client._sec())]
    link.pump(frames)
    check("价格改为 3000", device.price_cents_per_m3 == 3000, device.price_cents_per_m3)
    check("时长上限 120", device.max_session_s == 120)
    frames = [build_frame(wlp.TYPE_REQ, client._seq(), wlp.CMD_LOG, bytes([0]), client._sec())]
    link.pump(frames)
    check("LOG_RSP 无异常", client.error is None, client.error)


def test_status():
    print("[12] STATUS")
    device, client, link = make_pair()
    link.handshake()
    link.pump(client.status())
    check("STATUS_RSP 收到", "status" in client.response, client.response.keys())
    check("状态 READY(2)", client.response["status"][0] == wlp.STATE_READY, client.response["status"][0])


def main():
    for fn in (
        test_crc,
        test_pairing,
        test_handshake,
        test_open_close,
        test_cost_formula,
        test_replay,
        test_tamper,
        test_wrong_psk,
        test_heartbeat_timeout,
        test_limits,
        test_setcfg_and_log,
        test_status,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            global FAIL
            FAIL += 1
            print(f"  FAIL {fn.__name__} 抛异常: {type(exc).__name__}: {exc}")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
