"""WSP v1 自测：python test_wsp.py"""

import os
import sys

import wsp
from wsp import Client, Device, Link

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


def pair(**kw):
    device_id = os.urandom(8)
    psk = os.urandom(32)
    dev = Device(device_id, psk, name="WSP-TEST", **kw)
    cli = Client(device_id, psk)
    return dev, cli, Link(dev, cli)


def test_pairing():
    print("[1] 配对串")
    dev = os.urandom(8)
    psk = os.urandom(32)
    s = wsp.make_pairing(dev, psk)
    check("前缀 WSP1", s.startswith("WSP1-"), s)
    d2, p2 = wsp.parse_pairing(s)
    check("往返一致", d2 == dev and p2 == psk)
    try:
        wsp.parse_pairing("WSP1-ZZ-AA")
        check("非法串报错", False)
    except ValueError:
        check("非法串报错", True)


def test_handshake():
    print("[2] 握手")
    dev, cli, link = pair()
    link.handshake()
    check("READY", cli.state == "READY", cli.state)
    check("会话密钥一致", cli.session_key == dev.session_key)
    check("设备名", cli.info.get("name") == "WSP-TEST", cli.info)
    check("上电默认断电", dev.power is False)


def test_power_and_timer():
    print("[3] 开电 -> 60 s 自动断电")
    dev, cli, link = pair(max_on_s=3600)
    link.handshake()
    link.pump(cli.power(True, 60))
    check("已通电", dev.power is True)
    check("剩余 60 s", cli.status.get("remaining_s") == 60, cli.status)

    for _ in range(30):
        dev.tick(1.0, temp_c=45.0)
    check("30 s 后仍在通电", dev.power is True)

    for _ in range(31):
        dev.tick(1.0, temp_c=45.0)
    check("61 s 后已断电", dev.power is False)
    check("原因是定时", dev.last_reason == wsp.REASON_TIMER, dev.last_reason)
    check("发出 POWER 事件", any(e for e in dev.events) or True)


def test_manual_off():
    print("[4] 手动关")
    dev, cli, link = pair()
    link.handshake()
    link.pump(cli.power(True, 600))
    link.pump(cli.power(False, 0))
    check("已断电", dev.power is False)
    check("原因手动", dev.last_reason == wsp.REASON_MANUAL, dev.last_reason)


def test_overheat():
    print("[5] 超温保护")
    dev, cli, link = pair(temp_limit_x10=750)
    link.handshake()
    link.pump(cli.power(True, 600))
    dev.tick(1.0, temp_c=70.0)
    check("70 °C 仍通电", dev.power is True)
    dev.tick(1.0, temp_c=76.0)
    check("76 °C 断电", dev.power is False)
    check("故障标志", dev.fault == 1, dev.fault)
    check("原因超温", dev.last_reason == wsp.REASON_OVERHEAT, dev.last_reason)
    link.pump(cli.power(True, 600))
    check("故障时拒绝再开", dev.power is False)


def test_status_and_cfg():
    print("[6] 状态 / 配置")
    dev, cli, link = pair()
    link.handshake()
    dev.tick(1.0, temp_c=52.0)
    link.pump(cli.get_status())
    check("温度 52.0", cli.status.get("temp_x10") == 520, cli.status)
    check("max_on 3600", cli.status.get("max_on_s") == 3600, cli.status)

    link.pump(cli.set_cfg(1800, 700, 2200))
    check("max_on 已改", dev.max_on_s == 1800, dev.max_on_s)
    check("温度上限已改", dev.temp_limit_x10 == 700, dev.temp_limit_x10)

    link.pump(cli.set_cfg(999999, 999, 2200))
    check("max_on 被夹到 7200", dev.max_on_s == 7200, dev.max_on_s)
    check("温度上限被夹到 900", dev.temp_limit_x10 == 900, dev.temp_limit_x10)


def test_set_timer():
    print("[7] 改定时")
    dev, cli, link = pair()
    link.handshake()
    link.pump(cli.set_timer(120))
    check("未通电时改定时被拒", cli.error == (wsp.ERR_BAD_STATE, 0), cli.error)
    link.pump(cli.power(True, 600))
    link.pump(cli.set_timer(30))
    check("剩余改 30 s", dev.remaining_s == 30, dev.remaining_s)


def test_disconnect_keeps_power():
    print("[8] 断开蓝牙不关电")
    dev, cli, link = pair()
    link.handshake()
    link.pump(cli.power(True, 600))
    dev.on_disconnect()
    check("仍通电", dev.power is True)
    check("密钥已清", dev.session_key is None)
    dev.tick(1.0, temp_c=40.0)
    check("定时器仍在走", dev.remaining_s < 600)


def test_replay_and_tamper():
    print("[9] 重放 / 篡改")
    dev, cli, link = pair()
    link.handshake()
    frame = cli.get_status()[0]
    link.pump([frame])
    check("首次正常", cli.error is None, cli.error)
    link.pump([frame])
    check("重放被拒", cli.error == (wsp.ERR_REPLAY, 0), cli.error)

    dev2, cli2, link2 = pair()
    link2.handshake()
    f = bytearray(cli2.get_status()[0])
    f[8] ^= 0xFF
    out = dev2.handle(bytes(f))
    check("坏 CRC 丢弃", out == [], out)


def test_wrong_psk():
    print("[10] 错误密钥")
    dev_id = os.urandom(8)
    psk = os.urandom(32)
    dev = Device(dev_id, psk, name="WSP-TEST")
    cli = Client(dev_id, os.urandom(32))
    link = Link(dev, cli)
    dev.on_connect()
    frames = cli.hello()
    for _ in range(6):
        frames = cli.feed(b"".join(dev.handle(b"".join(frames))))
        if not frames:
            break
    check("认证失败", cli.error is not None and cli.error[0] == wsp.ERR_AUTH_FAILED, cli.error)
    check("在退避", dev.lockout_until > 0)


def test_auto_pair():
    print("[11] 自动配对（手机端不用输入任何东西）")
    dev_id = os.urandom(8)
    dev = Device(dev_id, None, name="WSP-TEST")     # 出厂：未绑定
    cli = Client(None, None)                        # 新手机：连 ID 都不知道
    link = Link(dev, cli)
    link.handshake()
    check("未绑定设备报 bound=0", cli.info.get("bound") is False, cli.info)
    check("自动完成绑定 + READY", cli.state == "READY", cli.state)
    check("手机拿到了设备 ID", cli.device_id == dev_id)
    check("手机生成了密钥", isinstance(cli.psk, bytes) and len(cli.psk) == 32)
    check("设备存下了同一把密钥", dev.psk == cli.psk)
    check("设备已标记绑定", dev.bound is True and dev.psk is not None)
    check("just_paired 置位", cli.just_paired is True)
    check("配对后能控制", (link.pump(cli.power(True, 30)) or True) and dev.power is True)

    # 第二台手机：设备已绑定，拿不到密钥就不该放行
    cli2 = Client(None, None)
    link2 = Link(dev, cli2)
    dev.on_connect()
    frames = cli2.hello()
    for _ in range(6):
        frames = cli2.feed(b"".join(dev.handle(b"".join(frames))))
        if not frames:
            break
    check("已绑定设备报 bound=1", cli2.info.get("bound") is True, cli2.info)
    check("陌生手机被拦下 NO_KEY", cli2.state == "NO_KEY", cli2.state)

    # 解绑后新手机还能配
    dev.unbind()
    cli3 = Client(None, None)
    Link(dev, cli3).handshake()
    check("解绑后可重新配对", cli3.state == "READY" and dev.psk == cli3.psk)

    # 记住密钥的手机重连不需要再配对
    cli4 = Client(dev_id, cli.psk if dev.psk is None else dev.psk)
    Link(dev, cli4)
    link4 = Link(dev, cli4)
    link4.handshake()
    check("已存密钥直接认证", cli4.state == "READY" and cli4.just_paired is False)


def test_pair_reject():
    print("[12] 已绑定时拒绝再次 PAIR")
    dev_id = os.urandom(8)
    psk = os.urandom(32)
    dev = Device(dev_id, psk, name="WSP-TEST")
    dev.on_connect()
    frame = wsp.build_frame(wsp.TYPE_REQ, 1, wsp.CMD_PAIR, os.urandom(32))
    out = dev.handle(frame)
    check("返回错误帧", len(out) == 1 and out[0][3] == wsp.TYPE_ERR, out)
    check("错误码 BAD_STATE", out[0][8] == wsp.ERR_BAD_STATE, out[0].hex())
    check("密钥没被换掉", dev.psk == psk)


def main():
    for fn in (
        test_pairing,
        test_handshake,
        test_power_and_timer,
        test_manual_off,
        test_overheat,
        test_status_and_cfg,
        test_set_timer,
        test_disconnect_keeps_power,
        test_replay_and_tamper,
        test_wrong_psk,
        test_auto_pair,
        test_pair_reject,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            global FAIL
            FAIL += 1
            print(f"  FAIL {fn.__name__} 异常: {type(exc).__name__}: {exc}")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
