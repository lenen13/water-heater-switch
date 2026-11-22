// 把 web/index.html 复制到两个地方：
//   docs/index.html      —— GitHub Pages 的入口（仓库设置里选 main /docs）
//   apk/www/index.html   —— Capacitor 打包 APK 时的 webDir
// 用法（在 waterctl 目录下）：node tools/sync_site.mjs
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const src = path.join(root, 'web', 'index.html');

if (!existsSync(src)) {
  console.error('✗ 找不到 web/index.html');
  process.exit(1);
}

const targets = [
  path.join(root, 'docs', 'index.html'),
  path.join(root, 'apk', 'www', 'index.html')
];

for (const dst of targets) {
  mkdirSync(path.dirname(dst), { recursive: true });
  copyFileSync(src, dst);
  console.log(`✓ ${path.relative(root, dst)}  (${statSync(dst).size} 字节)`);
}

// GitHub Pages 从 /docs 发布时，跳过 Jekyll 处理
writeFileSync(path.join(root, 'docs', '.nojekyll'), '');
console.log('✓ docs/.nojekyll');

const html = readFileSync(src, 'utf8');
if (!html.includes('WSP1-') || !html.includes('UUID_SERVICE')) {
  console.error('⚠ 复制过去的文件看起来不像控制页，检查 web/index.html');
  process.exit(1);
}
