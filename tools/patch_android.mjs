// 给 Capacitor 生成的 Android 工程补蓝牙权限（幂等，可重复运行）
// 用法（在 waterctl 目录下）：node tools/patch_android.mjs
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

if (xml.includes('android.permission.BLUETOOTH_SCAN')) {
  console.log('✓ 蓝牙权限已存在，跳过');
  process.exit(0);
}

// Android 12+ 用 BLUETOOTH_SCAN / BLUETOOTH_CONNECT；
// Android 11 及以下仍然要 BLUETOOTH / BLUETOOTH_ADMIN + 位置权限才能扫描。
const block = `    <!-- 蓝牙（WSP 开关） -->
    <uses-permission android:name="android.permission.BLUETOOTH_SCAN" android:usesPermissionFlags="neverForLocation" />
    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
    <uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" android:maxSdkVersion="30" />
    <uses-feature android:name="android.hardware.bluetooth_le" android:required="true" />

`;

const idx = xml.search(/<application\b/);
if (idx < 0) {
  console.error('✗ AndroidManifest.xml 里没有 <application> 标签，手动检查一下');
  process.exit(1);
}

xml = xml.slice(0, idx) + block + xml.slice(idx);
writeFileSync(manifest, xml, 'utf8');
console.log('✓ 已写入蓝牙权限：' + path.relative(root, manifest));
