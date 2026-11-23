// ============================================================================
//  原厂蓝牙水控器（WaterXXXXX）支持 —— 与 py/waterctl_proto.py 逐字节一致
//  这一段由 tools/bundle_water.mjs 注入 web/index.html（保持单文件）
// ============================================================================
(function () {
  'use strict';

  // ---------------------------------------------------------------- 常量
  const WATER_SERVICE = '0000f1f0-0000-1000-8000-00805f9b34fb';
  const WATER_TXD = '0000f1f1-0000-1000-8000-00805f9b34fb';
  const WATER_RXD = '0000f1f2-0000-1000-8000-00805f9b34fb';

  const WATER_START_PROLOGUE = [0xFE, 0xFE, 0x09, 0xB0, 0x01, 0x01, 0x00, 0x00];
  const WATER_END_PROLOGUE = [0xFE, 0xFE, 0x09, 0xB3, 0x00, 0x00];
  const WATER_OFFLINE_FIX = [0xFE, 0xFE, 0x09, 0xBC, 0x00, 0x00];
  const WATER_BA_ACK = [0xFE, 0xFE, 0x09, 0xBA, 0x00, 0x00];
  const WATER_PRICE_PER_M3 = 25;      // 元/吨，与原厂默认一致

  const DEPUTY_B64 = '__DEPUTY_B64__';

  // ---------------------------------------------------------------- 查表
  let DEPUTY = null;
  function table() {
    if (!DEPUTY) {
      const s = atob(DEPUTY_B64);
      DEPUTY = new Uint8Array(65536);          // 模拟 WASM 一页线性内存，越界读为 0
      for (let i = 0; i < s.length; i++) DEPUTY[i] = s.charCodeAt(i);
    }
    return DEPUTY;
  }
  const T = i => table()[i & 0xFFFF];

  // ---------------------------------------------------------------- 校验
  function crc16Changgong(text) {
    let crc = 0x1017;
    for (let k = 0; k < text.length; k++) {
      crc ^= text.charCodeAt(k) & 0xFF;
      for (let i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >>> 1) ^ 0xA001) : (crc >>> 1);
    }
    return crc & 0xFFFF;
  }
  function crc16Cgaeaf(bytes) {
    let crc = 0x6A1F;
    for (let k = 0; k < bytes.length; k++) {
      crc ^= bytes[k] & 0xFF;
      for (let i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >>> 1) ^ 0xA001) : (crc >>> 1);
    }
    return (crc ^ 0x75) & 0xFF;
  }
  function decAsHex(v) {
    if (v <= 0) return 0;
    return (v % 10) | (decAsHex(Math.floor(v / 10)) << 4);
  }

  // ---------------------------------------------------------------- key 算法
  function waterKey(a, b, c, d) {
    if (b === 0xFF && (a & 1)) a += 2;
    if (a === 257) a = 0;

    let ia = d & 7;
    const dHigh = d & ~7;
    for (const bit of [3, 4, 5, 6, 7]) if (dHigh & (1 << bit)) ia ^= 4;
    ia ^= T(b);
    const ks = [1, 1, 2, 7, 1, 1, 1, 1];
    for (let bit = 0; bit < 8; bit++) if (a & (1 << bit)) ia ^= ks[bit];

    let ic = c & 7;
    const cHigh = c & ~7;
    for (const bit of [3, 4, 5, 6, 7]) if (cHigh & (1 << bit)) ic ^= 4;
    ic ^= T(768 + (b & 15));

    d = T(256 + b) ^ d;
    d = T(512 + a) ^ d;
    const ib = T(1296 + d);

    c = T(784 + b) ^ c;
    c = T(1040 + a) ^ c;
    const id = T(1552 + c);

    return [T(1938 + ia), T(1808 + ib), T(2082 + ic), T(1952 + id)];
  }

  function waterUnlockResponse(req, deviceName) {
    if (req.length < 10) throw new Error('AE 帧太短');
    const unknown = req[5];
    const nonce = (req[6] << 8) | req[7];
    const macHi = req[8], macLo = req[9];
    let newNonce;
    if (nonce === 0xFFFF) newNonce = [0x01, 0x00];   // 原厂固件 bug：不回绕到 0
    else { const n = nonce + 1; newNonce = [(n >> 8) & 0xFF, n & 0xFF]; }

    const raw = waterKey(req[6], req[7], macHi, macLo);
    const mask = deviceName.slice(-4).split('').map(ch => ch.charCodeAt(0) - 0x30);
    const key = raw.map((x, i) => x ^ (mask[i] || 0));

    const body = [unknown, newNonce[0], newNonce[1], key[0], key[1], key[2], key[3],
      0xFE, 0x87, 0, 0, 0, 0, 0, 0];
    return [0xFE, 0xFE, 0x09, 0xAF, crc16Cgaeaf(body)].concat(body);
  }

  function randomUserId() {
    const n = 1 + Math.floor(Math.random() * 9999);
    return [decAsHex(n >> 8) & 0xFF, decAsHex(n & 0xFF) & 0xFF];
  }
  function nowArray() {
    const d = new Date();
    const vals = [d.getFullYear() % 100, d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
    return vals.map(v => decAsHex(v) & 0xFF);
  }
  function waterStartEpilogue(deviceName, keyAuth) {
    const sum = crc16Changgong(deviceName.slice(-5));
    const mn = keyAuth ? 0x0B : 0xFF;
    return [0xFE, 0xFE, 0x09, 0xB2, 0x01, sum & 0xFF, (sum >> 8) & 0xFF, mn, 0x00]
      .concat(randomUserId()).concat(nowArray()).concat([0x0F, 0x27, 0x00]);
  }

  function repairDeviceFrame(raw) {
    if (!raw || !raw.length) return null;
    if (raw[0] === 0xFD && raw[1] === 0xFD) return raw;
    if (raw.length === 1 && raw[0] === 0xFD) return null;
    if (raw[0] === 0xFD) return new Uint8Array([0xFD].concat(Array.from(raw)));
    if (raw[0] === 0x09) return new Uint8Array([0xFD, 0xFD].concat(Array.from(raw)));
    return raw;
  }

  const hexStr = a => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join(' ');

  // ---------------------------------------------------------------- 会话
  // 握手成功时原厂水控器就已经"开始出水"了（B2 是开始命令），所以状态里
  // FLOWING = 正在出水，点旋钮/快捷按钮 = 发送 B3 结束。
  class WaterSession {
    constructor(transport, deviceName) {
      this.t = transport;
      this.name = deviceName;
      this.state = 'NEW';         // NEW | HANDSHAKE | FLOWING | READY | ERROR
      this.keyAuth = false;
      this.volumeDl = 0;
      this.costYuan = 0;
      this.timer = null;
      transport.onNotify = c => this.feed(c);
    }

    async start() {
      this.state = 'HANDSHAKE';
      uiWater('握手中…', 'warn');
      await this.send(WATER_START_PROLOGUE);
      this.armTimeout();
    }

    armTimeout(ms) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        if (this.state === 'HANDSHAKE' || this.state === 'WAIT_START' || this.state === 'CLOSING') {
          this.fail('设备没有回应（超时）');
        }
      }, ms || 15000);
    }

    async send(bytes) {
      log('→ 水控器 ' + hexStr(bytes));
      await this.t.write(Uint8Array.from(bytes));
    }

    fail(msg) {
      clearTimeout(this.timer);
      this.state = 'ERROR';
      uiWater(msg, 'err');
      log('⚠ 水控器：' + msg);
      toast(msg);
    }

    feed(chunk) {
      const f = repairDeviceFrame(chunk);
      if (!f || f.length < 4) return;
      const cmd = f[3];
      log('← 水控器 ' + hexStr(f));
      switch (cmd) {
        case 0xB0:
        case 0xB1:                       // 旧固件：没有密钥认证，直接开始
          this.keyAuth = false;
          setTimeout(() => {
            if (this.state === 'HANDSHAKE') this.begin(false).catch(e => this.fail(e.message));
          }, 500);
          break;
        case 0xAE:                       // 新固件：密钥认证挑战
          this.send(waterUnlockResponse(f, this.name)).catch(e => this.fail(e.message));
          break;
        case 0xAF:
          if (f[5] === 0x55) {
            this.keyAuth = true;
            this.begin(true).catch(e => this.fail(e.message));
          } else {
            this.fail('密钥被拒绝（设备错误码 ' + (f[5] || 0) + '）');
          }
          break;
        case 0xB2:                       // 会话开始：正在出水
          this.state = 'FLOWING';
          clearTimeout(this.timer);
          uiWater('正在用水', 'ok');
          break;
        case 0xB3: {                     // 结束：末尾 3 字节小端 = 用量（0.1 L）
          const n = f.length;
          const dl = (f[n - 3] | (f[n - 2] << 8) | (f[n - 1] << 16)) >>> 0;
          this.volumeDl = dl;
          this.costYuan = dl / 10 * WATER_PRICE_PER_M3 / 1000;
          this.state = 'READY';
          clearTimeout(this.timer);
          uiWater('已结束 ' + (dl / 10).toFixed(1) + ' L / ' + this.costYuan.toFixed(2) + ' 元', 'ok');
          log('本次用水 ' + (dl / 10).toFixed(1) + ' L，约 ' + this.costYuan.toFixed(2) + ' 元');
          break;
        }
        case 0xBA:
          this.send(WATER_BA_ACK).catch(() => {});
          break;
        case 0xBC:
          this.send(WATER_OFFLINE_FIX).catch(() => {});
          break;
        case 0xC8:
          this.fail('水控器拒绝启动');
          break;
        default:
          break;   // 0xAA 遥测 / 0xB5 温度设置 / 0xB8 等，忽略
      }
    }

    async begin(keyAuth) {
      this.state = 'WAIT_START';
      clearTimeout(this.timer);
      await this.send(waterStartEpilogue(this.name, keyAuth));
      this.armTimeout(8000);
    }

    async close() {
      if (this.state !== 'FLOWING') { toast('当前没有在出水'); return; }
      this.state = 'CLOSING';
      await this.send(WATER_END_PROLOGUE);
      this.armTimeout(10000);
    }
  }

  // ---------------------------------------------------------------- 传输
  const norm = u => String(u || '').toLowerCase();

  class NativeTransport {
    constructor(deviceId, service, cmd, evt) {
      this.deviceId = deviceId;
      this.service = service;
      this.cmd = cmd;
      this.evtUuid = evt;
      this.onNotify = null;
      this.chain = Promise.resolve();
    }
    write(bytes) {
      const copy = Uint8Array.from(bytes);
      const job = async () => {
        const CHUNK = 180;
        for (let off = 0; off < copy.length; off += CHUNK) {
          const part = copy.subarray(off, Math.min(off + CHUNK, copy.length));
          await CapBle.write({
            deviceId: this.deviceId,
            service: this.service,
            characteristic: this.cmd,
            value: new DataView(part.buffer, part.byteOffset, part.byteLength)
          });
          if (off + CHUNK < copy.length) await new Promise(r => setTimeout(r, 12));
        }
      };
      this.chain = this.chain.catch(() => {}).then(job).catch(e => log('蓝牙写入失败：' + (e && e.message || e)));
      return this.chain;
    }
  }

  class WebTransport {
    constructor(charCmd, charEvt, evtUuid) {
      this.charCmd = charCmd;
      this.charEvt = charEvt;
      this.evtUuid = evtUuid;
      this.onNotify = null;
    }
    async write(bytes) {
      const CHUNK = 180;
      for (let off = 0; off < bytes.length; off += CHUNK) {
        const part = bytes.subarray(off, Math.min(off + CHUNK, bytes.length));
        if (this.charCmd.properties.writeWithoutResponse) await this.charCmd.writeValueWithoutResponse(part);
        else await this.charCmd.writeValueWithResponse(part);
        if (off + CHUNK < bytes.length) await new Promise(r => setTimeout(r, 12));
      }
    }
  }

  // ---------------------------------------------------------------- 界面
  let waterSession = null;

  function uiWater(text, cls) {
    const tag = document.getElementById('linkTag');
    if (tag) { tag.textContent = text; tag.className = 'tag' + (cls ? ' ' + cls : ''); }
    const flowing = waterSession && waterSession.state === 'FLOWING';
    const knob = document.getElementById('knob');
    const main = document.getElementById('knobMain');
    const sub = document.getElementById('knobSub');
    const t1 = knob && knob.querySelector('.t1');
    if (knob) {
      knob.classList.toggle('on', !!flowing);
      knob.classList.toggle('fault', cls === 'err');
    }
    if (main) main.textContent = flowing ? '正在用水' : (waterSession && waterSession.state === 'READY' ? '已关闭' : text);
    if (sub) sub.textContent = flowing ? '点按结束' : '轻点开关';
    if (t1) t1.textContent = flowing ? 'ON' : (cls === 'err' ? 'FAULT' : 'OFF');
    const mT = document.getElementById('mTemp');
    const mTot = document.getElementById('mTotal');
    const mSt = document.getElementById('mState');
    if (mT) mT.textContent = '--';
    if (mTot && waterSession) mTot.textContent = (waterSession.volumeDl / 10).toFixed(1) + ' L';
    if (mSt) mSt.textContent = flowing ? '用水' : (cls === 'err' ? '异常' : '待机');
  }

  // ---------------------------------------------------------------- 连接
  async function startWaterSession(transport, name) {
    APP.proto = 'water';
    APP.mode = 'ble';
    APP.name = name;
    APP.transport = transport;
    waterSession = new WaterSession(transport, name);
    APP.water = waterSession;
    setConnected(true, '已连接', 'ok');
    uiWater('握手中…', 'warn');
    await waterSession.start();
  }

  async function nativeWater(deviceId, name) {
    await CapBle.startNotifications({ deviceId, service: WATER_SERVICE, characteristic: WATER_RXD });
    const t = new NativeTransport(deviceId, WATER_SERVICE, WATER_TXD, WATER_RXD);
    await startWaterSession(t, name);
  }

  async function webWater(device, name) {
    const server = await device.gatt.connect();
    const svc = await server.getPrimaryService(WATER_SERVICE);
    const charCmd = await svc.getCharacteristic(WATER_TXD);
    const charEvt = await svc.getCharacteristic(WATER_RXD);
    await charEvt.startNotifications();
    const t = new WebTransport(charCmd, charEvt, WATER_RXD);
    charEvt.addEventListener('characteristicvaluechanged', ev => {
      const v = ev.target.value;
      if (t.onNotify) t.onNotify(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
    });
    await startWaterSession(t, name);
  }

  const isWaterName = n => /^water/i.test(n || '');

  // ---------------------------------------------------------------- 设备列表
  const seen = new Map();
  let scanning = false;
  let scanEndTimer = null;

  const pickerEl = () => document.getElementById('picker');

  function ensurePicker() {
    if (pickerEl()) return;
    const box = document.createElement('div');
    box.id = 'picker';
    box.className = 'sheet';
    box.innerHTML = '<div class="sheetBox">'
      + '<div class="sheetHead"><b>选择蓝牙设备</b><span id="pickHint">正在扫描…</span></div>'
      + '<div class="pickList" id="pickList"></div>'
      + '<div class="sheetFoot"><button class="btn" id="pickCancel">取消</button>'
      + '<button class="btn" id="pickSys">系统列表</button>'
      + '<button class="btn" id="pickAgain">重新扫描</button></div></div>';
    document.body.appendChild(box);
    box.addEventListener('click', e => { if (e.target === box) hidePicker(); });
    box.querySelector('#pickCancel').onclick = () => hidePicker();
    box.querySelector('#pickAgain').onclick = () => startScan();
    box.querySelector('#pickSys').onclick = () => systemListFallback();
  }

  function showPicker() { ensurePicker(); pickerEl().style.display = 'flex'; }
  function hidePicker() { const p = pickerEl(); if (p) p.style.display = 'none'; stopScan(); }

  function renderList() {
    const list = document.getElementById('pickList');
    if (!list) return;
    const rank = it => (isWaterName(it.name) || /^wsp-/i.test(it.name)) ? 0 : 1;
    const items = Array.from(seen.values()).sort((a, b) => {
      const d = rank(a) - rank(b);
      return d !== 0 ? d : (b.rssi || -999) - (a.rssi || -999);
    });
    if (!items.length) { list.innerHTML = '<div class="pickEmpty">还没发现设备，稍等两秒…</div>'; return; }
    const hint = document.getElementById('pickHint');
    if (hint && scanning) hint.textContent = '扫描中… 已发现 ' + items.length + ' 个';
    list.innerHTML = '';
    for (const it of items) {
      const row = document.createElement('button');
      row.className = 'pickRow';
      const known = rank(it) === 0;
      row.innerHTML = '<span class="nm">' + (it.name || '(无名设备)') + '</span>'
        + '<span class="rssi">' + (it.rssi === undefined ? '' : it.rssi + ' dBm') + '</span>'
        + (known ? ' <span class="badge">可控制</span>' : '');
      row.onclick = () => connectPicked(it.id, it.name);
      list.appendChild(row);
    }
  }

  async function startScan() {
    if (!NATIVE_BLE || !CapBle) return;
    ensurePicker();
    seen.clear();
    renderList();
    const hint = document.getElementById('pickHint');
    if (hint) hint.textContent = '正在扫描…';
    try {
      await CapBle.initialize({ androidNeverForLocation: true }).catch(() => CapBle.initialize());
      if (scanning) { try { await CapBle.stopLEScan(); } catch (e) {} }
      scanning = true;
      await CapBle.requestLEScan({ allowDuplicates: false });
      clearTimeout(scanEndTimer);
      scanEndTimer = setTimeout(() => {
        if (scanning) {
          stopScan();
          if (hint) hint.textContent = '扫描结束，可点「重新扫描」';
        }
      }, 12000);
    } catch (e) {
      scanning = false;
      const msg = String(e && e.message || e);
      if (hint) hint.textContent = '扫描失败：' + msg + '（可点「系统列表」）';
      log('扫描失败：' + msg);
      if (/permission|denied|拒绝/i.test(msg)) toast('请在系统设置里允许「附近的设备」权限');
      else toast('自主扫描失败，可点「系统列表」兜底');
    }
  }

  async function stopScan() {
    clearTimeout(scanEndTimer);
    if (!scanning) return;
    scanning = false;
    try { await CapBle.stopLEScan(); } catch (e) {}
  }

  // 兜底：如果自主扫描一个设备都没扫到，直接用系统的设备选择框（按名字前缀筛）。
  async function systemListFallback() {
    const hint = document.getElementById('pickHint');
    try {
      await stopScan();
      const device = await CapBle.requestDevice({
        namePrefix: 'Water',
        optionalServices: [WATER_SERVICE]
      });
      if (!device || !device.deviceId) return;
      connectPicked(device.deviceId, device.name || device.localName || 'Water');
    } catch (e) {
      const msg = String(e && e.message || e);
      if (hint) hint.textContent = '系统列表失败：' + msg;
      if (/cancel/i.test(msg)) return;
      // 再试一次：不按名字筛，用服务 UUID 筛
      try {
        const d2 = await CapBle.requestDevice({ services: [WATER_SERVICE], optionalServices: [WATER_SERVICE] });
        if (d2 && d2.deviceId) connectPicked(d2.deviceId, d2.name || d2.localName || 'Water');
      } catch (e2) {
        const m2 = String(e2 && e2.message || e2);
        if (hint) hint.textContent = '系统列表失败：' + m2;
        log('系统列表失败：' + m2);
      }
    }
  }

  async function connectPicked(deviceId, name) {
    hidePicker();
    try {
      setConnected(false, '连接中…', 'warn');
      await CapBle.connect({ deviceId });
      APP.link = deviceId;
      APP.name = name;
      if (isWaterName(name)) {
        await nativeWater(deviceId, name);
      } else {
        APP.proto = 'wsp';
        APP.mode = 'ble';
        await CapBle.startNotifications({ deviceId, service: UUID_SERVICE, characteristic: UUID_EVT });
        const t = new CapTransport(CapBle, deviceId);
        t.service = UUID_SERVICE;
        t.evtUuid = UUID_EVT;
        APP.transport = t;
        await setupSession(t, 'ble');
        setConnected(true, '已连接', 'ok');
      }
    } catch (e) {
      const msg = String(e && e.message || e);
      let hint = msg;
      if (msg.includes('Missing the following permissions')) hint = 'APK 清单缺权限：请装最新 APK。' + msg;
      else if (/cancel/i.test(msg)) hint = '已取消';
      else if (/No Services|not support|not found/i.test(msg)) hint = '这台设备不是能控制的类型（' + name + '）';
      log('连接失败：' + hint);
      toast('连接失败：' + hint);
      setConnected(false, '未连接', 'err');
    }
  }

  async function connectWeb() {
    try {
      const device = await navigator.bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: [UUID_SERVICE, WATER_SERVICE]
      });
      const name = device.name || '';
      APP.link = device;
      APP.name = name;
      device.addEventListener('gattserverdisconnected', () => {
        if (waterSession) waterSession.state = 'ERROR';
        APP.session = null;
        setConnected(false, '已断开', 'err');
      });
      setConnected(false, '连接中…', 'warn');
      if (isWaterName(name)) {
        await webWater(device, name);
      } else {
        const server = await device.gatt.connect();
        const svc = await server.getPrimaryService(UUID_SERVICE);
        const charCmd = await svc.getCharacteristic(UUID_CMD);
        const charEvt = await svc.getCharacteristic(UUID_EVT);
        await charEvt.startNotifications();
        const t = new BleTransport(charCmd, charEvt);
        charEvt.addEventListener('characteristicvaluechanged', ev => {
          const v = ev.target.value;
          if (t.onNotify) t.onNotify(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
        });
        APP.proto = 'wsp';
        APP.mode = 'ble';
        APP.transport = null;
        await setupSession(t, 'ble');
        setConnected(true, '已连接', 'ok');
      }
    } catch (e) {
      const msg = String(e && e.message || e);
      log('连接失败：' + msg);
      toast('连接失败：' + (/cancel/i.test(msg) ? '已取消' : msg));
      setConnected(false, '未连接', 'err');
    }
  }

  // ---------------------------------------------------------------- 事件
  if (NATIVE_BLE && CapBle) {
    CapBle.addListener('onScanResult', r => {
      const id = r.device && r.device.deviceId;
      const name = r.localName || (r.device && (r.device.name || r.device.localName)) || '';
      if (!id) return;
      if (!seen.has(id)) log('发现设备：' + (name || '(无名)') + '  ' + id);
      seen.set(id, { id, name, rssi: r.rssi });
      renderList();
    });
    CapBle.addListener('notification', ev => {
      const t = APP.transport;
      if (!t || !t.evtUuid) return;
      if (norm(ev.service) !== norm(t.service) || norm(ev.characteristic) !== norm(t.evtUuid)) return;
      if (t.onNotify) t.onNotify(new Uint8Array(ev.value.buffer, ev.value.byteOffset, ev.value.byteLength));
    });
    CapBle.addListener('disconnected', ev => {
      if (APP.link && ev.deviceId === APP.link) {
        APP.session = null;
        setConnected(false, '已断开', 'err');
        toast('连接已断开');
      }
    });
  }

  document.getElementById('btnConn').onclick = async () => {
    if (APP.session || waterSession) { disconnect(); waterSession = null; return; }
    if (NATIVE_BLE) { showPicker(); startScan(); return; }
    if (WEB_BLE) { connectWeb(); return; }
    explainNoBle();
  };

  document.getElementById('knob').onclick = async () => {
    if (APP.proto === 'water' && waterSession) {
      if (waterSession.state === 'FLOWING') await waterSession.close();
      else if (waterSession.state === 'READY') { await waterSession.begin(waterSession.keyAuth); }
      else toast('还没准备好');
      return;
    }
    const s = APP.session;
    if (!s || s.state !== 'READY') { toast(APP.session ? '还没握手完' : '先连接设备'); return; }
    const st = s.status || {};
    if (st.fault) { toast('保护中，请按设备上的按键清除故障'); return; }
    if (st.on) await s.power(false, 0); else await s.power(true, 0);
  };

  document.querySelectorAll('[data-preset]').forEach(btn => {
    btn.onclick = async () => {
      if (APP.proto === 'water' && waterSession) {
        if (waterSession.state === 'FLOWING') await waterSession.close();
        else if (waterSession.state === 'READY') await waterSession.begin(waterSession.keyAuth);
        return;
      }
      const s = APP.session;
      if (!s || s.state !== 'READY') { toast('先连接设备'); return; }
      const sec = parseInt(btn.dataset.preset, 10);
      if (sec === 0) { await s.power(true, 0); return; }
      if (s.status && s.status.on) await s.setTimer(sec); else await s.power(true, sec);
    };
  });

  if (typeof setBanner === 'function' && (NATIVE_BLE || WEB_BLE)) {
    const mode = NATIVE_BLE ? 'APK 原生蓝牙' : '浏览器蓝牙';
    setBanner('✅ <b>' + mode + '</b>就绪（构建 ' + (typeof BUILD === 'string' ? BUILD : '?') + '）：点「连接设备」会列出附近<b>所有</b>蓝牙设备。<br>'
      + '· <b>Water</b> 开头的原厂水控器 → 直接开关水；'
      + '· <b>WSP-</b> 开头的自制开关 → 自动配对后控制热水器电源。<br>'
      + '扫不到就点列表里的「系统列表」按钮兜底。', 'ok');
  }

  window.__WATER__ = { crc16Changgong, crc16Cgaeaf, waterKey, waterUnlockResponse, waterStartEpilogue, repairDeviceFrame };
})();
