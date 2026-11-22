# 热水器开关 · Android APK

这个目录是 [Capacitor](https://capacitorjs.com/) 外壳：把 `web/index.html` 原样装进一个安卓 App，
页面里的 Web Bluetooth 换成原生 BLE 插件（`@capacitor-community/bluetooth-le`）。

界面和协议跟网页版**完全同一份代码**，改网页就自动同步到 APK（`node tools/sync_site.mjs`）。

---

## 一、云端构建（推荐，不用装 Android 工具链）

仓库里已经有 `.github/workflows/build-apk.yml`，全部在 GitHub 的服务器上编译：

1. 把整个 `waterctl` 目录推到 GitHub 仓库（`main` 分支）。
2. 打开仓库页面 → **Actions** → 左边选 **build-apk** → 右边 **Run workflow** → `Run workflow`。
3. 等 5～10 分钟（第一次要下 Gradle 和 Android SDK，之后有缓存会快）。
4. 进去那次运行 → 页面底部 **Artifacts** → 下载 `wsp-heater-debug-apk.zip` → 解压得到 `app-debug.apk`。
5. 手机上装：把 apk 传给自己（微信/数据线/网盘），点开安装，允许"安装未知来源应用"。

> 这是 **debug 包**，用 Android 自动生成的调试证书签名，自己装着用没问题；
> 要上架或长期分发才需要正式签名（见下文"正式签名"）。

---

## 二、本地构建（已经有 Android Studio / JDK 17）

```bash
cd waterctl/apk
npm install                 # 装 Capacitor 和蓝牙插件
npm run sync:web            # 把 web/index.html 复制到 apk/www
npx cap add android         # 第一次才需要：生成 apk/android 工程
node ../tools/patch_android.mjs   # 补蓝牙权限
npx cap sync android        # 把 www 同步进 Android 工程
npm run build:debug:win     # Windows：apk/android/app/build/outputs/apk/debug/app-debug.apk
# macOS/Linux 用 npm run build:debug
```

`npx cap open android` 可以直接用 Android Studio 打开工程、接手机点运行。

---

## 三、权限说明（`tools/patch_android.mjs` 自动写入）

| 权限 | 用途 |
| --- | --- |
| `BLUETOOTH_SCAN`（neverForLocation） | Android 12+ 扫描设备 |
| `BLUETOOTH_CONNECT` | Android 12+ 连接设备 |
| `BLUETOOTH` / `BLUETOOTH_ADMIN`（maxSdk 30） | Android 11 及以下 |
| `ACCESS_FINE_LOCATION`（maxSdk 30） | Android 11 及以下扫描 BLE 必须给位置权限 |
| `uses-feature bluetooth_le` | 声明必需 BLE 硬件 |

第一次点「连接设备」时系统会弹权限框，全部允许即可。
如果只给了"附近设备"权限还是扫不到，去系统设置里把这台 App 的**位置信息**权限也打开（旧系统才有这问题）。

---

## 四、正式签名（可选）

1. 生成 keystore：
   ```bash
   keytool -genkey -v -keystore wsp-release.jks -alias wsp -keyalg RSA -keysize 2048 -validity 10000
   ```
2. `apk/android/app/build.gradle` 里加 `signingConfigs.release`，`buildTypes.release` 指向它。
3. 在 CI 里用 GitHub Secrets 传 keystore（base64）和密码，改跑 `assembleRelease`。

自己用的话不用折腾，debug 包就够。

---

## 五、常见问题

- **装完打开是白屏？** 先看是不是 `npx cap sync android` 忘了跑（`www/index.html` 没进工程）。
- **能扫到设备但连不上？** 确认固件广播名是 `WSP-XXXX`，服务 UUID 是 `57535031-0001-...`。
- **换了手机需要重新配对吗？** 不需要配对码：新手机连上后设备如果已绑定，会提示"长按设备按键 5 秒解绑"，解绑后再连一次就自动配对。
- **APK 里的蓝牙和网页版有什么区别？** 只有传输层不同（`CapTransport` vs `BleTransport`），协议、界面、密钥存储逻辑都一样。
