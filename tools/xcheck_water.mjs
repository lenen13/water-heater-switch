// 交叉验证：把 web/water.js（原厂水控器协议）在 Node 里跑起来，与 py/waterctl_proto.py 的
// 期望值逐字节比对。用法（在 waterctl 目录下）：node tools/xcheck_water.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const page = readFileSync(path.join(root, 'web', 'index.html'), 'utf8');
const b64 = readFileSync(path.join(root, 'py', 'deputy_table.b64.txt'), 'utf8').replace(/\s+/g, '');
// 用真实表替换占位符后求值（页面里是注入后的版本，这里校验源码本身）
const js = readFileSync(path.join(root, 'web', 'water.js'), 'utf8')
  .replace("'__DEPUTY_B64__'", "'" + b64 + "'");

let pass = 0, fail = 0;
const ok = (name, cond, extra) => {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? '  ' + extra : '')); }
};
const hex = a => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');

// ---------- 浏览器环境桩 ----------
const el = () => ({
  onclick: null, style: {}, textContent: '', innerHTML: '', className: '', dataset: {},
  classList: { toggle() {}, add() {}, remove() {} },
  querySelector: () => el(), querySelectorAll: () => [],
  appendChild() {}, addEventListener() {}, remove() {}
});
const documentStub = {
  getElementById: () => el(),
  createElement: () => el(),
  querySelectorAll: () => [],
  body: el(),
  addEventListener() {}
};
const windowObj = {};
const APP = { session: null, proto: null, mode: null, link: null };

const factory = new Function(
  'window', 'document', 'toast', 'log', 'setConnected', 'uiWater', 'explainNoBle', 'APP', 'TIPS',
  'NATIVE_BLE', 'WEB_BLE', 'CapBle', 'UUID_SERVICE', 'UUID_CMD', 'UUID_EVT',
  'setupSession', 'CapTransport', 'BleTransport', 'disconnect', 'setBanner',
  js + '\n;return window.__WATER__;'
);

let W;
try {
  W = factory(windowObj, documentStub, () => {}, () => {}, () => {}, () => {}, () => {}, APP, [],
    false, false, null, 'svc', 'cmd', 'evt', () => {}, function () {}, function () {}, () => {}, () => {});
} catch (e) {
  console.error('✗ web/water.js 运行出错：' + e.message);
  process.exit(1);
}
if (!W) { console.error('✗ 没有导出 window.__WATER__'); process.exit(1); }

// ---------- 与 py/waterctl_proto.py 一致的期望值 ----------
console.log('· 校验（期望值由 py/waterctl_proto.py 生成）');
ok('crc16Changgong("33982") = 0x9b39', W.crc16Changgong('33982') === 0x9b39);
ok('crc16Changgong("11070") = 0xd015', W.crc16Changgong('11070') === 0xd015);
ok('waterKey(00,05,95,27) = c05992c6', hex(W.waterKey(0x00, 0x05, 0x95, 0x27)) === 'c05992c6',
  hex(W.waterKey(0x00, 0x05, 0x95, 0x27)));

const req1 = Uint8Array.from([0xfd, 0xfd, 0x09, 0xae, 0x38, 0x00, 0x00, 0x05, 0x95, 0x27,
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]);
ok('AE → AF（非 0xffff nonce）逐字节一致',
  hex(W.waterUnlockResponse(req1, 'Water33982')) === 'fefe09af72000006c3509ac4fe87000000000000',
  hex(W.waterUnlockResponse(req1, 'Water33982')));

const req4 = Uint8Array.from([0xfd, 0xfd, 0x09, 0xae, 0x9f, 0x00, 0xff, 0xff, 0x95, 0x27,
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]);
ok('AE → AF（nonce=0xffff 边界）逐字节一致',
  hex(W.waterUnlockResponse(req4, 'Water33982')) === 'fefe09afd9000100d6ac3f3bfe87000000000000',
  hex(W.waterUnlockResponse(req4, 'Water33982')));

const epi = W.waterStartEpilogue('Water33982', false);
const eh = hex(epi);
ok('B2 长度 20 且头部 fe fe 09 b2 01', epi.length === 20 && eh.startsWith('fefe09b201'));
ok('B2 第 5/6 字节 = crc16Changgong 小端（39 9b）', epi[5] === 0x39 && epi[6] === 0x9b, eh);
ok('B2 旧固件 mn=0xff、第 8 字节 0x00', epi[7] === 0xFF && epi[8] === 0x00);
ok('B2 尾部 0f 27 00', epi[17] === 0x0f && epi[18] === 0x27 && epi[19] === 0x00);
const epi2 = W.waterStartEpilogue('Water33982', true);
ok('B2 新固件 mn=0x0b', epi2[7] === 0x0B);

// ---------- 收包修补 ----------
const rep = (arr) => Array.from(W.repairDeviceFrame(Uint8Array.from(arr)) || []);
ok('缺 1 字节 0xFD 的帧被补齐', hex(rep([0xfd, 0x09, 0xaf, 0x55])) === 'fdfd09af55');
ok('缺 2 字节的帧被补齐', hex(rep([0x09, 0xaf, 0x55])) === 'fdfd09af55');
ok('单字节 0xFD 被丢弃', W.repairDeviceFrame(Uint8Array.from([0xfd])) === null);

// ---------- 注入结果自检 ----------
console.log('· 注入自检');
ok('index.html 含 WATER-BEGIN 标记', page.includes('<!-- WATER-BEGIN -->'));
ok('index.html 含真实 base64 表（非占位符）',
  page.includes(b64.slice(0, 64)) && !page.includes("'__DEPUTY_B64__'"));
ok('index.html 含 picker 样式', page.includes('.pickRow'));
ok('注入块在 </body> 之前',
  page.indexOf('<!-- WATER-END -->') < page.lastIndexOf('</body>'));

console.log('');
// ---------- 结束流程：B3 -> 设备回 B3 -> B4 -> 断开 ----------
{
  const sent = [];
  const t = { onNotify: null, write: async b => { sent.push(hex(b)); } };
  const s = new W.WaterSession(t, 'Water41177');
  let ended = false;
  s.onEnded = () => { ended = true; };
  s.state = 'FLOWING';
  await s.close();
  ok('结束流程先发 B3', sent[0] === 'fefe09b30000', sent[0]);
  const reply = Uint8Array.from([
    0xfd, 0xfd, 0x09, 0xb3,
    0x38, 0xbb, 0x02, 0x00, 0x70, 0xe2, 0xeb, 0x20,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00
  ]);
  s.feed(reply);
  ok('B3 回包算出用量 2.8 L', s.volumeDl === 28, String(s.volumeDl));
  ok('B3 回包后发 B4', sent[1] === 'fefe09b40000', sent[1]);
  await new Promise(r => setTimeout(r, 400));
  ok('结束完成后触发断开回调', ended === true);
}

console.log(pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
