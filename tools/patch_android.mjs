// 给 Capacitor 生成的 Android 工程补蓝牙权限（幂等，可重复运行）
// 用法（在 waterctl 目录下）：node tools/patch_android.mjs
//
// 两个坑（都踩过）：
//  1) ACCESS_FINE_LOCATION 如果写成 android:maxSdkVersion="30"，
//     Capacitor 在 Android 12+ 上会认为"清单里没有这个权限"，于是
//     @capacitor-community/bluetooth-le 直接抛
//     Missing the following permissions in AndroidManifest.xml: ACCESS_FINE_LOCATION
//     —— 所以这里不写 maxSdkVersion，让它对所有版本都声明。
//  2) 老版本脚本写的权限块要能被替换掉，否则重复构建会留下旧的那行。
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const manifest = path.join(root, 'apk', 'android', 'app', 'src', 'main', 'AndroidManifest.xml');

if (!existsSync(manifest)) {
  console.error('✗ 找不到 AndroidManifest.xml，先执行：cd apk && npx cap add android');
  process.exit(1);
}

let xml = readFileSync(manifest, 'utf8');

const MARK = '<!-- 蓝牙（WSP 开关） -->';

// Android 12+ 用 BLUETOOTH_SCAN / BLUETOOTH_CONNECT；
// Android 11 及以下仍然要 BLUETOOTH / BLUETOOTH_ADMIN + 位置权限才能扫描。
// 位置权限不写 maxSdkVersion：Capacitor 的权限别名检查是按"当前系统版本是否声明"来判断的。
const block = `    ${MARK}
    <uses-permission android:name="android.permission.BLUETOOTH_SCAN" android:usesPermissionFlags="neverForLocation" />
    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
    <uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <uses-feature android:name="android.hardware.bluetooth_le" android:required="true" />

`;

// 1. 先删掉旧脚本写入的整块（从 MARK 到 uses-feature 那一行）
if (xml.includes(MARK)) {
  const start = xml.indexOf(MARK);
  const featIdx = xml.indexOf('android.hardware.bluetooth_le', start);
  const endTag = featIdx >= 0 ? xml.indexOf('>', featIdx) : -1;
  if (endTag >= 0) {
    let end = endTag + 1;
    while (end < xml.length && (xml[end] === '\r' || xml[end] === '\n')) end++;
    xml = xml.slice(0, start) + xml.slice(end);
    console.log('· 已移除旧的权限块');
  }
}

// 2. 兜底：任何残留的 ACCESS_FINE_LOCATION maxSdkVersion="30" 行也清掉
xml = xml.replace(/[ \t]*<uses-permission android:name="android\.permission\.ACCESS_FINE_LOCATION"[^>]*\/>\r?\n/g, '');
xml = xml.replace(/[ \t]*<uses-permission android:name="android\.permission\.ACCESS_COARSE_LOCATION"[^>]*\/>\r?\n/g, '');

// 3. 插到 <application> 前面
const idx = xml.search(/<application\b/);
if (idx < 0) {
  console.error('✗ AndroidManifest.xml 里没有 <application> 标签，手动检查一下');
  process.exit(1);
}
xml = xml.slice(0, idx) + block + xml.slice(idx);

writeFileSync(manifest, xml, 'utf8');

// 4. 自检：确认关键几行真的在里面
const must = [
  'android.permission.BLUETOOTH_SCAN',
  'android.permission.BLUETOOTH_CONNECT',
  'android.permission.ACCESS_FINE_LOCATION'
];
const missing = must.filter(k => !xml.includes(k));
if (missing.length) {
  console.error('✗ 写入后仍然缺少：' + missing.join(', '));
  process.exit(1);
}
if (/ACCESS_FINE_LOCATION"[^>]*maxSdkVersion/.test(xml)) {
  console.error('✗ ACCESS_FINE_LOCATION 还带着 maxSdkVersion，会导致 12+ 上被判为"缺失"');
  process.exit(1);
}

console.log('✓ 已写入蓝牙权限：' + path.relative(root, manifest));
console.log(xml.slice(Math.max(0, xml.indexOf('    ' + MARK) - 0), xml.indexOf('>', xml.indexOf('android.hardware.bluetooth_le')) + 1));
