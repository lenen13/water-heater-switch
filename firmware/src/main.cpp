// ===========================================================================
//  WSP v1 —— 蓝牙热水器开关（继电器版）参考固件
//  ESP32-C3 + NimBLE-Arduino 1.4.x，PlatformIO 编译
//
//  协议：../py/wsp.py（Python 参考实现，36 项测试通过）
//  文档：../蓝牙热水器开关方案.md
//
//  接线：
//    GPIO5  继电器 IN（高电平=通电；模块务必选"低电平触发可跳线"或光耦隔离型）
//    GPIO0  NTC 10k B3950（10k 上拉到 3V3），贴在水箱外壳或出水口，做超温保护
//    GPIO8  WS2812 状态灯（蓝=待机，绿=通电，红=故障）
//    GPIO9  按键（BOOT，低有效）：短按开关，长按 5 秒解绑（换手机用）
//
//  ★ 安全：市电部分必须装在阻燃接线盒里，走线用足够线径，
//    继电器触点容量要 ≥ 热水器额定电流的 1.5 倍。第一次测试请先接灯泡，不要直接接热水器。
// ===========================================================================

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <esp_mac.h>
#include <esp_system.h>
#include <mbedtls/md.h>

// --------------------------------------------------------------------------
// 1. 常量
// --------------------------------------------------------------------------
static const char *UUID_SERVICE = "57535031-0001-4b1e-9d3a-0c0ffee0beef";
static const char *UUID_CMD     = "57535031-0002-4b1e-9d3a-0c0ffee0beef";
static const char *UUID_EVT     = "57535031-0003-4b1e-9d3a-0c0ffee0beef";
static const char *DEVICE_PREFIX = "WSP-";

static const uint8_t MAGIC[2] = {0xA5, 0x5A};
static const uint16_t MAX_PAYLOAD = 512;

enum : uint8_t { TYPE_REQ = 0x01, TYPE_RSP = 0x02, TYPE_EVT = 0x03, TYPE_ERR = 0x04, TYPE_SECURED = 0x80 };

enum : uint8_t {
  CMD_HELLO = 0x01, CMD_HELLO_RSP = 0x81,
  CMD_AUTH_BEGIN = 0x02, CMD_AUTH_CHALLENGE = 0x82,
  CMD_AUTH_FINISH = 0x03, CMD_AUTH_OK = 0x83,
  CMD_PAIR = 0x04, CMD_PAIR_OK = 0x84,
  CMD_SET_POWER = 0x10, CMD_POWER_ACK = 0x90,
  CMD_SET_TIMER = 0x11, CMD_TIMER_ACK = 0x91,
  CMD_GET_STATUS = 0x20, CMD_STATUS_RSP = 0xA0,
  CMD_SET_CFG = 0x21, CMD_CFG_ACK = 0xA1,
  EVT_POWER = 0xE1, EVT_FAULT = 0xE2, EVT_TICK = 0xE5,
};

enum : uint8_t {
  ERR_BAD_FRAME = 0x01, ERR_BAD_CRC = 0x02, ERR_BAD_STATE = 0x03,
  ERR_AUTH_REQUIRED = 0x04, ERR_AUTH_FAILED = 0x05, ERR_REPLAY = 0x06,
  ERR_LIMIT = 0x07, ERR_BUSY = 0x08, ERR_UNKNOWN_CMD = 0x09, ERR_LOCKED_OUT = 0x0A,
};

enum : uint8_t { REASON_MANUAL = 1, REASON_TIMER = 2, REASON_OVERHEAT = 3, REASON_BUTTON = 4, REASON_SAFEBOOT = 5 };

// 引脚
static const int PIN_RELAY = 5;
static const int PIN_NTC = 0;
static const int PIN_LED = 8;
static const int PIN_BTN = 9;

// 默认配置（可用 APP 里的 SET_CFG 改，存 NVS）
static uint32_t cfgMaxOnS = 3600;      // 一次最多通电 1 小时
static int16_t  cfgTempLimitX10 = 750; // 75.0 °C 强制断电
static uint16_t cfgNominalW = 2000;    // 铭牌功率，仅用于 App 估算电量
static const uint32_t TICK_MS = 100;

// --------------------------------------------------------------------------
// 2. 工具
// --------------------------------------------------------------------------
static inline void put_u16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }
static inline void put_u32(uint8_t *p, uint32_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF; }
static inline uint16_t get_u16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static inline uint32_t get_u32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

static uint16_t crc16_ccitt(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int b = 0; b < 8; b++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

static void hmac_sha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, data, len);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// 注意：Arduino-ESP32 6.x 的 mbedtls 没有编 MBEDTLS_HKDF_C，
// 直接调 mbedtls_hkdf() 会链接失败（undefined reference）。
// 这里按 RFC 5869 用 HMAC-SHA256 手写，输出长度正好 32 字节（一个块）。
static void hkdf_sha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen,
                        const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen) {
  static const uint8_t zero32[32] = {0};
  uint8_t prk[32];
  hmac_sha256(saltLen ? salt : zero32, saltLen ? saltLen : 32, ikm, ikmLen, prk);

  uint8_t t[32];
  size_t tLen = 0, done = 0;
  uint8_t counter = 1;
  while (done < outLen) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, prk, 32);
    if (tLen) mbedtls_md_hmac_update(&ctx, t, tLen);
    if (infoLen) mbedtls_md_hmac_update(&ctx, info, infoLen);
    mbedtls_md_hmac_update(&ctx, &counter, 1);
    mbedtls_md_hmac_finish(&ctx, t);
    mbedtls_md_free(&ctx);

    tLen = 32;
    size_t n = (outLen - done < 32) ? (outLen - done) : 32;
    memcpy(out + done, t, n);
    done += n;
    counter++;
  }
}

static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static String base32(const uint8_t *d, size_t n) {
  String s;
  uint32_t buf = 0;
  int bits = 0;
  for (size_t i = 0; i < n; i++) {
    buf = (buf << 8) | d[i];
    bits += 8;
    while (bits >= 5) { s += B32[(buf >> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) s += B32[(buf << (5 - bits)) & 31];
  return s;
}

// --------------------------------------------------------------------------
// 3. 状态
// --------------------------------------------------------------------------
static Preferences prefs;
static uint8_t deviceId[8];
static uint8_t psk[32];
static bool bound = false;          // 是否已经被某台手机配对过（出厂为 false）
static const uint16_t CAPS_BOUND = 0x8000;
static char devName[24];

static bool power = false;
static bool connected = false;
static float remainingS = 0;
static float totalOnS = 0;
static float tempC = 25.0f;
static uint8_t fault = 0;
static uint8_t lastReason = REASON_SAFEBOOT;
static uint32_t lastTickMs = 0;

static uint8_t sessionKey[32];
static bool haveKey = false;
static uint8_t cnonce[16], dnonce[16];
static bool haveCnonce = false, haveDnonce = false;
static uint32_t dnonceAt = 0;
static int lastSeq = -1;
static uint8_t seqOut = 0;
static uint8_t authFails = 0;
static uint32_t lockoutUntil = 0;

static NimBLECharacteristic *evtChar = nullptr;

// --------------------------------------------------------------------------
// 4. 硬件
// --------------------------------------------------------------------------
static void relay_set(bool on) {
  power = on;
  digitalWrite(PIN_RELAY, on ? HIGH : LOW);
  neopixelWrite(PIN_LED, fault ? 60 : 0, on ? 60 : 0, on ? 0 : 60);
}

static float read_ntc() {
  int mv = analogReadMilliVolts(PIN_NTC);
  if (mv <= 20 || mv >= 3280) return -100.0f;
  float r = 10000.0f * (float)mv / (3300.0f - (float)mv);
  return 1.0f / (1.0f / 298.15f + logf(r / 10000.0f) / 3950.0f) - 273.15f;
}

static void force_off(uint8_t reason) {
  if (!power) return;
  relay_set(false);
  remainingS = 0;
  lastReason = reason;
  uint8_t p[6];
  p[0] = 0;
  put_u32(p + 1, 0);
  p[5] = reason;
  uint8_t buf[64];
  uint16_t n = 0;
  // 事件帧
  buf[0] = MAGIC[0]; buf[1] = MAGIC[1]; buf[2] = 0x01;
  buf[3] = TYPE_EVT | (haveKey ? TYPE_SECURED : 0);
  put_u16(buf + 4, 6);
  buf[6] = seqOut = (uint8_t)(seqOut + 1);
  buf[7] = EVT_POWER;
  memcpy(buf + 8, p, 6);
  n = 14;
  if (haveKey) {
    uint8_t mac[32];
    hmac_sha256(sessionKey, 32, buf, n, mac);
    memcpy(buf + n, mac, 4);
    n += 4;
  }
  put_u16(buf + n, crc16_ccitt(buf, n));
  n += 2;
  if (connected && evtChar) {
    evtChar->setValue(buf, n);
    evtChar->notify();
  }
}

// --------------------------------------------------------------------------
// 5. 帧收发
// --------------------------------------------------------------------------
static uint16_t build_frame(uint8_t *out, uint8_t type_, uint8_t seq, uint8_t cmd,
                            const uint8_t *payload, uint16_t len, const uint8_t *key) {
  bool sec = key != nullptr;
  uint16_t n = 0;
  out[n++] = MAGIC[0];
  out[n++] = MAGIC[1];
  out[n++] = 0x01;
  out[n++] = type_ | (sec ? TYPE_SECURED : 0);
  put_u16(out + n, len); n += 2;
  out[n++] = seq;
  out[n++] = cmd;
  if (len) { memcpy(out + n, payload, len); n += len; }
  if (sec) {
    uint8_t mac[32];
    hmac_sha256(key, 32, out, n, mac);
    memcpy(out + n, mac, 4);
    n += 4;
  }
  put_u16(out + n, crc16_ccitt(out, n));
  return n + 2;
}

static void ble_send(const uint8_t *data, uint16_t len) {
  if (!connected || !evtChar) return;
  uint16_t mtu = NimBLEDevice::getMTU();
  uint16_t chunk = (mtu > 23) ? (uint16_t)(mtu - 3) : 20;
  for (uint16_t off = 0; off < len; off += chunk) {
    uint16_t rem = (uint16_t)(len - off);
    uint16_t n = (chunk < rem) ? chunk : rem;
    evtChar->setValue(data + off, n);
    evtChar->notify();
    delay(3);
  }
}

static uint8_t next_seq() { seqOut = (uint8_t)(seqOut + 1); return seqOut; }

static void send_rsp(uint8_t cmd, const uint8_t *payload = nullptr, uint16_t len = 0, bool secured = true) {
  uint8_t buf[560];
  uint16_t n = build_frame(buf, TYPE_RSP, next_seq(), cmd, payload, len, secured ? sessionKey : nullptr);
  ble_send(buf, n);
}

static void send_err(uint8_t code, uint8_t detail = 0) {
  uint8_t p[2] = {code, detail};
  uint8_t buf[64];
  uint16_t n = build_frame(buf, TYPE_ERR, next_seq(), CMD_HELLO_RSP, p, 2, nullptr);
  ble_send(buf, n);
}

// --------------------------------------------------------------------------
// 6. 业务
// --------------------------------------------------------------------------
static void save_cfg() {
  prefs.putUInt("maxon", cfgMaxOnS);
  prefs.putShort("tlim", cfgTempLimitX10);
  prefs.putUShort("watt", cfgNominalW);
}

static void power_on(uint32_t durationS) {
  if (fault) return;
  uint32_t dur = durationS == 0 ? cfgMaxOnS : durationS;
  if (dur > cfgMaxOnS) dur = cfgMaxOnS;
  remainingS = (float)dur;
  relay_set(true);
  lastReason = 0;
}

static void handle_frame(uint8_t type, uint8_t seq, uint8_t cmd, const uint8_t *pl, uint16_t len) {
  bool secured = (type & TYPE_SECURED) != 0;

  if (cmd == CMD_HELLO) {
    uint8_t p[64];
    memcpy(p, deviceId, 8);
    p[8] = 0; p[9] = 1; p[10] = 0;
    put_u16(p + 11, (uint16_t)(0x0006 | (bound ? CAPS_BOUND : 0)));
    put_u16(p + 13, 244);
    size_t nl = strlen(devName);
    p[15] = (uint8_t)nl;
    memcpy(p + 16, devName, nl);
    send_rsp(CMD_HELLO_RSP, p, (uint16_t)(16 + nl), false);
    return;
  }

  // 首次配对：零输入。手机连上后自己生成 32 字节密钥发过来，设备存下就算绑定。
  if (cmd == CMD_PAIR) {
    if (bound) { send_err(ERR_BAD_STATE); return; }
    if (len != 32) { send_err(ERR_BAD_FRAME); return; }
    memcpy(psk, pl, 32);
    prefs.putBytes("psk", psk, 32);
    prefs.putBool("bound", true);
    bound = true;
    Serial.printf("[PAIR] 已与首台手机绑定，设备名 %s\n", devName);
    send_rsp(CMD_PAIR_OK, deviceId, 8, false);
    return;
  }

  if (cmd == CMD_AUTH_BEGIN) {
    if (!bound) { send_err(ERR_AUTH_FAILED); return; }
    if (millis() < lockoutUntil) { send_err(ERR_LOCKED_OUT); return; }
    if (len != 16) { send_err(ERR_BAD_FRAME); return; }
    memcpy(cnonce, pl, 16);
    haveCnonce = true;
    esp_fill_random(dnonce, 16);
    haveDnonce = true;
    dnonceAt = millis();
    lastSeq = -1;
    send_rsp(CMD_AUTH_CHALLENGE, dnonce, 16, false);
    return;
  }

  if (cmd == CMD_AUTH_FINISH) {
    if (!bound) { send_err(ERR_AUTH_FAILED); return; }
    if (!haveCnonce || !haveDnonce) { send_err(ERR_BAD_STATE); return; }
    if (millis() - dnonceAt > 60000) { send_err(ERR_REPLAY); return; }
    if (len < 16) { send_err(ERR_BAD_FRAME); return; }

    uint8_t msg[9 + 8 + 16 + 16];
    uint8_t mac[32];
    memcpy(msg, "WSP1-AUTH", 9);
    memcpy(msg + 9, deviceId, 8);
    memcpy(msg + 17, cnonce, 16);
    memcpy(msg + 33, dnonce, 16);
    hmac_sha256(psk, 32, msg, sizeof(msg), mac);

    if (memcmp(mac, pl, 16) != 0) {
      authFails++;
      uint32_t backoff = (authFails >= 9) ? 300000UL : (1000UL << (authFails - 1));
      if (backoff > 300000UL) backoff = 300000UL;
      lockoutUntil = millis() + backoff;
      send_err(ERR_AUTH_FAILED, authFails);
      return;
    }

    uint8_t salt[32];
    memcpy(salt, cnonce, 16);
    memcpy(salt + 16, dnonce, 16);
    hkdf_sha256(psk, 32, salt, 32, (const uint8_t *)"WSP1-SESSION", 12, sessionKey, 32);
    haveKey = true;
    authFails = 0;

    uint8_t macs[32];
    memcpy(msg, "WSP1-ACK", 8);
    memcpy(msg + 8, deviceId, 8);
    memcpy(msg + 16, dnonce, 16);
    memcpy(msg + 32, cnonce, 16);
    hmac_sha256(psk, 32, msg, 48, macs);

    uint8_t out[18];
    memcpy(out, macs, 16);
    put_u16(out + 16, 1);
    uint8_t buf[64];
    uint16_t n = build_frame(buf, TYPE_RSP, next_seq(), CMD_AUTH_OK, out, 18, nullptr);
    ble_send(buf, n);

    haveCnonce = haveDnonce = false;
    return;
  }

  if (!haveKey || !secured) { send_err(ERR_AUTH_REQUIRED); return; }
  if (lastSeq >= 0) {
    uint8_t delta = (uint8_t)(seq - lastSeq);
    if (delta == 0 || delta > 127) { send_err(ERR_REPLAY); return; }
  }
  lastSeq = seq;

  switch (cmd) {
    case CMD_SET_POWER: {
      if (len < 5) { send_err(ERR_BAD_FRAME); return; }
      bool want = pl[0] != 0;
      uint32_t dur = get_u32(pl + 1);
      if (want) {
        if (fault) { send_err(ERR_LIMIT); return; }
        power_on(dur);
      } else {
        relay_set(false);
        remainingS = 0;
        lastReason = REASON_MANUAL;
      }
      uint8_t p[6];
      p[0] = power ? 1 : 0;
      put_u32(p + 1, (uint32_t)remainingS);
      p[5] = lastReason;
      send_rsp(CMD_POWER_ACK, p, 6);
      return;
    }
    case CMD_SET_TIMER: {
      if (len < 4) { send_err(ERR_BAD_FRAME); return; }
      if (!power) { send_err(ERR_BAD_STATE); return; }
      uint32_t sec = get_u32(pl);
      if (sec < 1) sec = 1;
      if (sec > cfgMaxOnS) sec = cfgMaxOnS;
      remainingS = (float)sec;
      uint8_t p[4];
      put_u32(p, sec);
      send_rsp(CMD_TIMER_ACK, p, 4);
      return;
    }
    case CMD_GET_STATUS: {
      uint8_t p[16];
      p[0] = power ? 1 : 0;
      put_u32(p + 1, (uint32_t)remainingS);
      put_u16(p + 5, (uint16_t)(tempC * 10));
      put_u32(p + 7, (uint32_t)totalOnS);
      put_u32(p + 11, cfgMaxOnS);
      p[15] = fault;
      send_rsp(CMD_STATUS_RSP, p, 16);
      return;
    }
    case CMD_SET_CFG: {
      if (len >= 8) {
        uint32_t maxOn = get_u32(pl);
        int16_t tlim = (int16_t)get_u16(pl + 4);
        uint16_t watt = get_u16(pl + 6);
        cfgMaxOnS = maxOn < 60 ? 60 : (maxOn > 7200 ? 7200 : maxOn);
        cfgTempLimitX10 = tlim < 400 ? 400 : (tlim > 900 ? 900 : tlim);
        cfgNominalW = watt;
        if (power && remainingS > cfgMaxOnS) remainingS = (float)cfgMaxOnS;
        save_cfg();
      }
      send_rsp(CMD_CFG_ACK, nullptr, 0);
      return;
    }
    default:
      send_err(ERR_UNKNOWN_CMD, cmd);
  }
}

// --------------------------------------------------------------------------
// 7. 流式解析
// --------------------------------------------------------------------------
static uint8_t rxBuf[600];
static uint16_t rxLen = 0;

static void rx_append(const uint8_t *data, uint16_t len) {
  if (len > sizeof(rxBuf)) return;
  if (rxLen + len > sizeof(rxBuf)) rxLen = 0;
  memcpy(rxBuf + rxLen, data, len);
  rxLen += len;
}

static void rx_pump() {
  for (;;) {
    uint16_t i = 0;
    while (i + 1 < rxLen && !(rxBuf[i] == MAGIC[0] && rxBuf[i + 1] == MAGIC[1])) i++;
    if (i + 1 >= rxLen) { rxLen = 0; return; }
    if (i) { memmove(rxBuf, rxBuf + i, rxLen - i); rxLen -= i; }
    if (rxLen < 8) return;

    uint8_t type = rxBuf[3];
    uint16_t plen = get_u16(rxBuf + 4);
    if (plen > MAX_PAYLOAD) { memmove(rxBuf, rxBuf + 1, --rxLen); continue; }
    bool sec = (type & TYPE_SECURED) != 0;
    uint16_t total = (uint16_t)(8 + plen + (sec ? 4 : 0) + 2);
    if (rxLen < total) return;

    if (crc16_ccitt(rxBuf, total - 2) != get_u16(rxBuf + total - 2)) {
      memmove(rxBuf, rxBuf + 1, --rxLen);
      continue;
    }
    if (sec) {
      if (!haveKey) { memmove(rxBuf, rxBuf + total, rxLen - total); rxLen -= total; continue; }
      uint8_t mac[32];
      hmac_sha256(sessionKey, 32, rxBuf, (size_t)(total - 6), mac);
      if (memcmp(mac, rxBuf + total - 6, 4) != 0) {
        memmove(rxBuf, rxBuf + total, rxLen - total);
        rxLen -= total;
        continue;
      }
    }

    handle_frame(type, rxBuf[6], rxBuf[7], rxBuf + 8, plen);
    memmove(rxBuf, rxBuf + total, rxLen - total);
    rxLen -= total;
  }
}

// --------------------------------------------------------------------------
// 8. BLE 回调
// --------------------------------------------------------------------------
class CmdCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic *c) override {
    NimBLEAttValue v = c->getValue();
    rx_append((const uint8_t *)v.data(), (uint16_t)v.size());
    rx_pump();
  }
};

class ServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer *, ble_gap_conn_desc *) override {
    connected = true;
    haveKey = false;
    haveCnonce = haveDnonce = false;
    lastSeq = -1;
    rxLen = 0;
    Serial.printf("[BLE] 连接 mtu=%d\n", NimBLEDevice::getMTU());
  }
  void onDisconnect(NimBLEServer *) override {
    // 关键：断开蓝牙不关继电器，否则"开一会儿"就失去意义；定时器由设备自己兜底
    connected = false;
    haveKey = false;
    rxLen = 0;
    NimBLEDevice::startAdvertising();
    Serial.println("[BLE] 断开（继电器状态保持不变）");
  }
};

// --------------------------------------------------------------------------
// 9. 初始化
// --------------------------------------------------------------------------
static void load_identity() {
  prefs.begin("wsp", false);
  bound = prefs.getBool("bound", false) && prefs.getBytesLength("psk") == 32;
  if (bound) {
    prefs.getBytes("psk", psk, 32);
  } else {
    memset(psk, 0, sizeof(psk));   // 未绑定：密钥等第一台手机 PAIR 过来
  }
  if (prefs.getBytesLength("devid") == 8) {
    prefs.getBytes("devid", deviceId, 8);
  } else {
    uint8_t mac[6] = {0};
    esp_efuse_mac_get_default(mac);
    memcpy(deviceId, mac, 6);
    esp_fill_random(deviceId + 6, 2);
    prefs.putBytes("devid", deviceId, 8);
  }
  cfgMaxOnS = prefs.getUInt("maxon", 3600);
  cfgTempLimitX10 = prefs.getShort("tlim", 750);
  cfgNominalW = prefs.getUShort("watt", 2000);
  snprintf(devName, sizeof(devName), "%s%02X%02X", DEVICE_PREFIX, deviceId[6], deviceId[7]);
}

static void print_pairing() {
  Serial.println();
  Serial.printf("设备名 : %s\n", devName);
  if (!bound) {
    Serial.println("状态   : 未绑定 —— 用手机连一次即可（会打印配对记录）");
    Serial.println("================================\n");
    return;
  }
  Serial.println("========== WSP 配对串（备份用，正常连接不需要它） ==========");
  Serial.printf("配对串 : WSP1-%02X%02X%02X%02X%02X%02X%02X%02X-%s\n",
                deviceId[0], deviceId[1], deviceId[2], deviceId[3],
                deviceId[4], deviceId[5], deviceId[6], deviceId[7],
                base32(psk, 32).c_str());
  Serial.println("================================");
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(300);

  pinMode(PIN_RELAY, OUTPUT);
  digitalWrite(PIN_RELAY, LOW);   // 上电默认断电（失效安全）
  pinMode(PIN_BTN, INPUT_PULLUP);
  analogReadResolution(12);

  load_identity();
  print_pairing();

  NimBLEDevice::init(devName);
  NimBLEDevice::setMTU(247);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  NimBLEServer *server = NimBLEDevice::createServer();
  server->setCallbacks(new ServerCallbacks());

  NimBLEService *svc = server->createService(UUID_SERVICE);
  NimBLECharacteristic *cmdChar = svc->createCharacteristic(UUID_CMD, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  cmdChar->setCallbacks(new CmdCallbacks());
  evtChar = svc->createCharacteristic(UUID_EVT, NIMBLE_PROPERTY::NOTIFY);
  svc->start();

  NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(UUID_SERVICE);
  adv->setName(devName);
  // NimBLE-Arduino 1.4.x 的 API 是 setScanResponse(bool)；
  // 2.x 才改名 enableScanResponse，用错会编译失败。
  adv->setScanResponse(true);
  adv->start();

  relay_set(false);
  Serial.printf("[BOOT] 广播中: %s，默认断电\n", devName);
}

// --------------------------------------------------------------------------
// 10. 主循环
// --------------------------------------------------------------------------
void loop() {
  uint32_t now = millis();
  float dt = TICK_MS / 1000.0f;

  tempC = read_ntc();

  if (power) {
    remainingS -= dt;
    totalOnS += dt;

    if (tempC > cfgTempLimitX10 / 10.0f) {
      fault = 1;
      force_off(REASON_OVERHEAT);
      uint8_t fp[2] = {1, (uint8_t)max(0.0f, tempC)};
      uint8_t buf[64];
      uint16_t n = build_frame(buf, TYPE_EVT, next_seq(), EVT_FAULT, fp, 2, haveKey ? sessionKey : nullptr);
      if (connected) ble_send(buf, n);
    } else if (remainingS <= 0) {
      force_off(REASON_TIMER);
    }
  }

  // 1 Hz 上报
  if (now - lastTickMs >= 1000) {
    lastTickMs = now;
    if (connected && haveKey) {
      uint8_t p[7];
      p[0] = power ? 1 : 0;
      put_u32(p + 1, (uint32_t)max(0.0f, remainingS));
      put_u16(p + 5, (uint16_t)(tempC * 10));
      uint8_t buf[64];
      uint16_t n = build_frame(buf, TYPE_EVT, next_seq(), EVT_TICK, p, 7, sessionKey);
      ble_send(buf, n);
    }
  }

  // 按键：短按开关，长按 5 秒解绑（换手机时用）
  static bool btnWasDown = false;
  static uint32_t btnDownAt = 0;
  bool down = digitalRead(PIN_BTN) == LOW;
  if (down && !btnWasDown) btnDownAt = now;
  if (down && now - btnDownAt > 5000) {
    Serial.println("[BTN] 长按 -> 解绑，下一台手机可以直接配对");
    bound = false;
    memset(psk, 0, sizeof(psk));
    prefs.remove("psk");
    prefs.putBool("bound", false);
    haveKey = false;
    print_pairing();
    btnDownAt = now + 60000;
  } else if (!down && btnWasDown && now - btnDownAt > 40 && now - btnDownAt < 2000) {
    if (power) {
      relay_set(false);
      remainingS = 0;
      lastReason = REASON_BUTTON;
    } else {
      fault = 0;
      power_on(cfgMaxOnS);
    }
  }
  btnWasDown = down;

  delay(TICK_MS);
}
