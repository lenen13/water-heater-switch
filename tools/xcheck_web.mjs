// 交叉验证：把 web/index.html 里的协议层原样抽出来，在 Node 里跑，与 py/wsp.py 的期望值逐字节比对。
// 用法（在 waterctl 目录下）：node tools/xcheck_web.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const html = readFileSync(path.join(here, '..', 'web', 'index.html'), 'utf8');

const START = 'const UUID_SERVICE';
const END = '// ===================== 界面';
const i = html.indexOf(START);
const j = html.indexOf(END);
if (i < 0 || j < 0 || j <= i) {
  console.error('✗ 找不到抽取标记（const UUID_SERVICE / // 界面）');
  process.exit(1);
}

const stubs = "const log = () => {};\nconst toast = () => {};\nconst fmtLeft = s => String(Math.round(s));\n";const exportsList = [
  'crc16ccitt', 'hex', 'unhex', 'base32Encode', 'base32Decode', 'makePairing', 'parsePairing',
  'makeFrame', 'syncFrame', 'FrameReader', 'hmacSha256', 'hkdfSha256', 'authMacClient',
  'authMacDevice', 'deriveSessionKey', 'Session', 'SimDevice', 'SimTransport', 'CMD',
  'T_REQ', 'T_RSP', 'T_EVT', 'T_ERR'
];
const src = stubs + html.slice(i, j) + '\nexport { ' + exportsList.join(', ') + ' };\n';

const mod = await import('data:text/javascript;base64,' + Buffer.from(src, 'utf8').toString('base64'));

// 整段内联脚本的语法检查（只解析不执行）：协议层切片之外的部分（UI）有语法错也能抓到
try {
  const body = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'));
  new Function(body);
  console.log('✓ 内联脚本语法正确');
} catch (e) {
  console.error('✗ 内联脚本语法错误：' + e.message);
  process.exit(1);
}

// ---------- 期望值（由 py/wsp.py 生成）----------
const DEV = '1112131415161718';
const PAIRING = 'WSP1-1112131415161718-AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ';
const B32 = 'AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ';
const HELLO = 'a55a010100000101512a';
const HKDF = 'b7d7c957e00928c370374bf900604d7f77334480c01bfa6f999313ecbabd7c12';
const MAC_C = '2ecac98058236957ea796aa4d2a1d56b';
const MAC_S = '913408b899633b72231ef5bc97a47576';
const POWER_FRAME = 'a55a018105000210018403000044a874e1c508';
const CFG_FRAME = 'a55a018108000321100e0000ee02d0072a9621a662dc';

const devId = mod.unhex(DEV);
const psk = Uint8Array.from({ length: 32 }, (_, k) => k);
const cn = Uint8Array.from({ length: 16 }, (_, k) => k);
const dn = Uint8Array.from({ length: 16 }, (_, k) => k + 16);

let pass = 0, fail = 0;
function eq(name, got, want) {
  const ok = String(got) === String(want);
  if (ok) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}\n      得到 ${got}\n      期望 ${want}`); }
}

console.log('— 基础函数 —');
eq('crc16("123456789")', mod.crc16ccitt(new TextEncoder().encode('123456789')), 10673);
eq('base32(psk)', mod.base32Encode(psk), B32);
eq('makePairing', mod.makePairing(devId, psk), PAIRING);

const parsed = mod.parsePairing(PAIRING);
eq('parsePairing.deviceId', Buffer.from(parsed.deviceId).toString('hex'), DEV);
eq('parsePairing.psk', Buffer.from(parsed.psk).toString('hex'), Buffer.from(psk).toString('hex'));

console.log('— 帧与密码学 —');
eq('明文 HELLO 帧', Buffer.from(mod.syncFrame(mod.T_REQ, 1, mod.CMD.HELLO)).toString('hex'), HELLO);

const key = await mod.deriveSessionKey(psk, cn, dn);
eq('HKDF 会话密钥', Buffer.from(key).toString('hex'), HKDF);
eq('mac_c', Buffer.from(await mod.authMacClient(psk, devId, cn, dn)).toString('hex'), MAC_C);
eq('mac_s', Buffer.from(await mod.authMacDevice(psk, devId, cn, dn)).toString('hex'), MAC_S);

const powerPayload = new Uint8Array([1, 0x84, 0x03, 0, 0]);
eq('加密 SET_POWER 帧', Buffer.from(await mod.makeFrame(mod.T_REQ, 2, mod.CMD.SET_POWER, powerPayload, key)).toString('hex'), POWER_FRAME);

const cfgPayload = new Uint8Array([0x10, 0x0E, 0, 0, 0xEE, 0x02, 0xD0, 0x07]);
eq('加密 SET_CFG 帧', Buffer.from(await mod.makeFrame(mod.T_REQ, 3, mod.CMD.SET_CFG, cfgPayload, key)).toString('hex'), CFG_FRAME);

console.log('— 收包重组 —');
{
  const full = mod.unhex(POWER_FRAME);
  const r = new mod.FrameReader();
  eq('半包第一段解析出 0 帧', r.push(full.subarray(0, 7)).length, 0);
  const got = r.push(full.subarray(7));
  eq('半包补全后解析出 1 帧', got.length, 1);
  eq('重组后命令', got[0] && got[0].cmd, mod.CMD.SET_POWER);
  eq('重组后 payload', got[0] && Buffer.from(got[0].payload).toString('hex'), '0184030000');
  eq('识别为加密帧', got[0] && got[0].secured, true);
}
{
  const stream = mod.unhex('deadbeef' + HELLO + HELLO);
  const r = new mod.FrameReader();
  const got = r.push(stream);
  eq('带垃圾前缀 + 粘两帧 → 2 帧', got.length, 2);
}
{
  const bad = mod.unhex(POWER_FRAME);
  bad[bad.length - 1] ^= 0xFF; // 破坏 CRC
  const r = new mod.FrameReader();
  eq('坏 CRC 被丢弃', r.push(bad).length, 0);
}

console.log('— 端到端：JS 客户端 ↔ JS 模拟设备 —');
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function waitFor(cond, ms = 2000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (cond()) return true; await sleep(5); }
  return false;
}
function mkStore() {
  const m = new Map();
  return {
    map: m,
    get: id => m.get(Buffer.from(id).toString('hex')) || null,
    save: (id, k) => m.set(Buffer.from(id).toString('hex'), k.slice()),
    forget: id => m.delete(Buffer.from(id).toString('hex'))
  };
}

{
  // 未绑定设备：新手机什么都不用输入，自动配对 + 认证
  const store = mkStore();
  const dev = new mod.SimDevice(devId, null, 'WSP-SIM');
  const transport = new mod.SimTransport(dev);
  const ses = new mod.Session(transport, { keyStore: store });
  const errs = [];
  ses.onError = m => errs.push(m);
  transport.onNotify = c => { ses.feed(c).catch(e => console.log('  feed error', e)); };
  await ses.start();
  eq('自动配对完成 READY', await waitFor(() => ses.state === 'READY'), true);
  eq('HELLO 设备名', ses.info && ses.info.name, 'WSP-SIM');
  eq('设备报未绑定', ses.info && ses.info.bound, false);
  eq('justPaired', ses.justPaired, true);
  eq('手机学到了 deviceId', Buffer.from(ses.deviceId).toString('hex'), DEV);
  eq('设备存下同一把密钥', Buffer.from(dev.psk).toString('hex'), Buffer.from(ses.psk).toString('hex'));
  eq('密钥写进了 keyStore', Buffer.from(store.get(devId)).toString('hex'), Buffer.from(ses.psk).toString('hex'));

  await ses.power(true, 60);
  eq('开电后 on', await waitFor(() => ses.status.on === 1), true);
  eq('倒计时 60', Math.round(ses.status.remaining_s), 60);

  await dev.tick(61, 24);
  let out = dev.out.splice(0);
  for (const c of out) transport.onNotify(c);
  eq('到点自动断电', await waitFor(() => ses.status.on === 0), true);

  dev.tempX10 = 800;
  await ses.power(true, 0);
  await waitFor(() => ses.status.on === 1);
  await dev.tick(1, 80);
  out = dev.out.splice(0);
  for (const c of out) transport.onNotify(c);
  eq('超温断电 + fault', await waitFor(() => ses.status.fault === 1), true);

  await ses.power(true, 0);
  eq('故障中再开电被拒（LIMIT）', await waitFor(() => errs.some(e => e.includes('LIMIT'))), true);
}

{
  // 设备已绑定，这台手机存过密钥 -> 直接认证，不再配对
  const store = mkStore();
  const dev = new mod.SimDevice(devId, psk, 'WSP-SIM');
  store.save(devId, psk);
  const transport = new mod.SimTransport(dev);
  const ses = new mod.Session(transport, { keyStore: store });
  transport.onNotify = c => { ses.feed(c).catch(() => {}); };
  await ses.start();
  eq('已存密钥直接 READY', await waitFor(() => ses.state === 'READY'), true);
  eq('没有重新配对', ses.justPaired, false);
}

{
  // 设备已绑定，但这台手机没密钥 -> NO_KEY，不能硬闯
  const store = mkStore();
  const dev = new mod.SimDevice(devId, psk, 'WSP-SIM');
  const transport = new mod.SimTransport(dev);
  const ses = new mod.Session(transport, { keyStore: store });
  const errs = [];
  ses.onError = m => errs.push(m);
  transport.onNotify = c => { ses.feed(c).catch(() => {}); };
  await ses.start();
  eq('陌生手机被拦下', await waitFor(() => ses.state === 'NO_KEY'), true);
  eq('给出解绑提示', errs.some(e => e.includes('长按')), true);
}

{
  // 已绑定时设备必须拒绝 PAIR
  const dev = new mod.SimDevice(devId, psk, 'WSP-SIM');
  const frame = mod.syncFrame(mod.T_REQ, 1, mod.CMD.PAIR, new Uint8Array(32).fill(9));
  const out = await dev.handle(frame);
  eq('拒绝再次 PAIR，回错误帧', out.length === 1 && out[0][3] === mod.T_ERR, true);
  eq('错误码 BAD_STATE', out[0][8], 0x03);
  eq('原密钥没被换掉', Buffer.from(dev.psk).toString('hex'), Buffer.from(psk).toString('hex'));
}

{
  const dev = new mod.SimDevice(devId, psk, 'WSP-SIM');
  const transport = new mod.SimTransport(dev);
  const store = mkStore();
  store.save(devId, new Uint8Array(32).fill(7));
  const ses = new mod.Session(transport, { keyStore: store });
  transport.onNotify = c => { ses.feed(c).catch(() => {}); };
  await ses.start();
  eq('错误 PSK 不放行', await waitFor(() => ses.state === 'FAIL'), true);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
