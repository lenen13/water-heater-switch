// 把 web/water.js（原厂水控器支持）注入 web/index.html，保持单文件、可直接双击打开。
// 用法（在 waterctl 目录下）：node tools/bundle_water.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const pagePath = path.join(root, 'web', 'index.html');
const jsPath = path.join(root, 'web', 'water.js');
const b64Path = path.join(root, 'py', 'deputy_table.b64.txt');

const page = readFileSync(pagePath, 'utf8');
const js = readFileSync(jsPath, 'utf8');
const b64 = readFileSync(b64Path, 'utf8').replace(/\s+/g, '');

if (!/^[A-Za-z0-9+/=]+$/.test(b64) || b64.length !== 2796) {
  console.error('✗ deputy_table.b64.txt 内容异常：长度 ' + b64.length + '（应为 2796）');
  process.exit(1);
}
if (!js.includes("'__DEPUTY_B64__'")) {
  console.error('✗ web/water.js 里找不到 __DEPUTY_B64__ 占位符');
  process.exit(1);
}

const injected = js.replace("'__DEPUTY_B64__'", "'" + b64 + "'");
if (injected === js) {
  console.error('✗ base64 替换没有生效');
  process.exit(1);
}

const css = `
/* WATER-CSS：原厂水控器设备列表 */
.sheet{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:99;padding:16px}
.sheetBox{background:var(--card,#182130);border:1px solid rgba(255,255,255,.08);border-radius:18px;width:100%;max-width:420px;max-height:80vh;display:flex;flex-direction:column;overflow:hidden}
.sheetHead{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;font-size:15px;border-bottom:1px solid rgba(255,255,255,.06)}
.sheetHead span{font-size:12px;opacity:.65}
.pickList{overflow-y:auto;padding:6px}
.pickRow{display:flex;align-items:center;gap:8px;width:100%;background:transparent;border:0;border-radius:12px;padding:12px;color:inherit;font-size:14px;text-align:left;cursor:pointer}
.pickRow:hover,.pickRow:active{background:rgba(255,255,255,.06)}
.pickRow .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pickRow .rssi{font-size:12px;opacity:.55}
.pickRow .badge{font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(56,180,120,.18);color:#4fd39b;white-space:nowrap}
.pickEmpty{padding:28px 16px;text-align:center;opacity:.6;font-size:13px}
.sheetFoot{display:flex;gap:10px;padding:12px 16px;border-top:1px solid rgba(255,255,255,.06)}
.sheetFoot .btn{flex:1}
`;

const block = `<!-- WATER-BEGIN -->
<style id="waterCss">${css}</style>
<script>
${injected}
</script>
<!-- WATER-END -->
`;

let out;
const begin = '<!-- WATER-BEGIN -->';
const end = '<!-- WATER-END -->';
const bi = page.indexOf(begin);
const ei = page.indexOf(end);

if (bi >= 0 && ei > bi) {
  out = page.slice(0, bi) + block + page.slice(ei + end.length + 1);
  console.log('· 已替换旧的注入块');
} else {
  const bodyEnd = page.lastIndexOf('</body>');
  if (bodyEnd < 0) { console.error('✗ 找不到 </body>'); process.exit(1); }
  out = page.slice(0, bodyEnd) + block + page.slice(bodyEnd);
  console.log('· 已插入注入块');
}

// 自检
const must = ['WATER-BEGIN', 'waterCss', 'DEPUTY_B64', 'waterUnlockResponse', 'WATER-END'];
for (const k of must) {
  if (!out.includes(k)) { console.error('✗ 注入结果缺少 ' + k); process.exit(1); }
}
writeFileSync(pagePath, out, 'utf8');
console.log('✓ web/index.html 已更新：' + page.length + ' → ' + out.length + ' 字节');
console.log('  下一步：node tools/xcheck_web.mjs 然后 node tools/sync_site.mjs');
