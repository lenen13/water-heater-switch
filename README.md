# 蓝牙热水器：原厂协议解构 + 自己做一台开关

这个仓库有两部分：

1. **逆向**：把 [waterctl](https://github.com/celesWuff/waterctl)（开源蓝牙水控器，官网已下线）的协议逐字节拆开，给出可运行的参考实现。
2. **自研**：在它的基础上重新设计，做一台**自己能用的蓝牙热水器开关**（网页版控制，后续可打包成 APK）。

## 先看哪个

| 你想干什么 | 打开 |
| --- | --- |
| 直接开始做开关（BOM、接线、烧写、测试） | [`蓝牙热水器开关方案.md`](蓝牙热水器开关方案.md) |
| 搞懂原厂水控器是怎么工作的 | [`水控器协议解构.md`](水控器协议解构.md) |
| 看带阀门/计费那套水控器设计（WLP） | [`自研蓝牙热水器方案.md`](自研蓝牙热水器方案.md) |
| 没有硬件，先点着玩玩 | 浏览器打开 `web/index.html` → 右上角「模拟」 |

## 手机端：`web/index.html`

单文件，无依赖，不需要后端。

- 大圆钮开关、15/30/45/60 分钟定时、倒计时环、水温、故障提示
- 设置项存在设备里（最长通电、超温阈值、功率）
- 首次连接自动配对，密钥按设备 ID 存 localStorage
- **模拟设备模式**：没硬件也能完整体验（同协议、同加密，还会模拟超温和到点断电）

打开方式：
- 电脑：`python -m http.server 8000` 后访问 `http://localhost:8000/web/`
- 手机正式用：必须 **https**（GitHub Pages / 任意静态托管），`http://192.168.x.x` 用不了蓝牙
- 手机临时用：`cloudflared tunnel --url http://localhost:8000` 拿一个临时 https 地址
- 安卓只想连局域网：`edge://flags/#unsafely-treat-insecure-origin-as-secure` 把 `http://192.168.x.x:8000` 加白
- **不要用微信/QQ 打开 HTML 文件**：那是 `content://` 本地引用，不是网页，Chromium 系浏览器会白屏，蓝牙也不可能可用
- iPhone：用 Bluefy 浏览器（Safari 不支持 Web Bluetooth）

## 发布到 GitHub Pages（手机正式用）

页面里没有后端，放到任何静态托管都能用；用 GitHub Pages 最省事、且自带 https。

1. 把整个 `waterctl` 目录推成一个 GitHub 仓库（默认分支 `main`）。
2. 仓库页面 → **Settings** → 左侧 **Pages** → **Source** 选 *Deploy from a branch* → Branch 选 `main`，目录选 **`/docs`** → **Save**。
3. 等 1～2 分钟，地址是 `https://<你的用户名>.github.io/<仓库名>/`。
4. 手机 Chrome/Edge 打开这个地址 → 点「连接设备」→ 在系统弹窗里点 `WSP-XXXX`。

`docs/index.html` 不是手写的，是 `node tools/sync_site.mjs` 从 `web/index.html` 复制过去的（`docs/.nojekyll` 关闭 Jekyll）。改完网页记得重新跑一次：

```powershell
node tools/sync_site.mjs
```

> 没有装 Git 也能发：在 GitHub 网页上新建仓库，然后把 `docs`、`apk`、`tools`、`web`、`.github` 这些文件夹直接拖进上传页面（Chrome/Edge 支持整文件夹拖拽），保持目录结构即可。

## 打包成 APK（手机安装包）

APK 用 [Capacitor](https://capacitorjs.com/) 把同一份 `web/index.html` 装进壳里，Web Bluetooth 换成原生蓝牙插件。详见 [`apk/README.md`](apk/README.md)。

**推荐：GitHub Actions 云端编译**（本地不用装 Android SDK）

1. 仓库 → **Actions** → **build-apk** → **Run workflow**。
2. 跑完在那次运行页面底部下载 `wsp-heater-debug-apk` → 解压得 `app-debug.apk`。
3. 传到手机安装（允许"安装未知来源应用"）。

本地构建：`cd apk && npm install && npm run sync:web && npx cap add android && node ../tools/patch_android.mjs && npx cap sync android && npm run build:debug:win`。

**过渡方案**：不想装 APK 也行 —— 手机浏览器打开 Pages 地址后选「添加到主屏幕」，用起来就是一个全屏 App（PWA），蓝牙一样能用。


## 固件：`firmware/`

ESP32-C3 + NimBLE-Arduino，Protocol `WSP v1`。

```bash
cd firmware
pio run -t upload      # 编译并烧写
pio device monitor     # 115200，开机打印设备名/绑定状态
```

行为要点：上电默认断电；定时器在设备里跑（**手机离开也会到点断电**）；超温强制断电并要求人工按键确认；蓝牙断开**不会**关掉继电器。

## 验证（不需要硬件）

```powershell
cd py
python selftest.py        # 38 passed —— 原厂协议复刻正确
python test_wlp.py        # 51 passed —— 阀门版 WLP 可用
python test_wsp.py        # 51 passed —— 开关版 WSP 可用（含零输入自动配对）

cd ..
node tools/xcheck_web.mjs # 38 passed —— 网页端与 Python 逐字节一致 + 自动配对/模拟握手端到端
```

`selftest.py` 用的是原厂仓库 `src/algorithms.spec.ts`、`src/solvers.spec.ts` 里的全部测试向量（`deviceName = "Water33982"` 的 7 组 AE→AF 挑战应答），能全过说明对 `deputy.wat`（WASM 查表）的反推是逐字节正确的。

## 目录

```
py/
  waterctl_proto.py   原厂协议复刻（含 2096 字节查表，纯 Python）
  selftest.py         原厂协议 38 项测试向量
  deputy_table.bin    从 deputy.wat 抽出的 2096 字节表
  wlp.py / test_wlp.py  带阀门计费的 WLP v1（参考）
  wsp.py / test_wsp.py  热水器开关 WSP v1（当前在用）
firmware/
  platformio.ini      ESP32-C3 工程
  src/main.cpp        WSP 开关固件（BLE + 帧解析 + 继电器 + NTC 超温 + NVS）
web/
  index.html          手机端控制页（含模拟设备 + 原生 BLE 通道，供 APK 复用）
docs/
  index.html          GitHub Pages 发布入口（由 tools/sync_site.mjs 生成，勿手改）
  .nojekyll
apk/
  package.json        Capacitor 6 工程（蓝牙插件 @capacitor-community/bluetooth-le）
  capacitor.config.json
  www/index.html      由 sync_site.mjs 复制进来，打包前会自动同步
  README.md           APK 构建/安装/签名说明
.github/workflows/
  build-apk.yml       GitHub Actions 云端编译 debug APK
tools/
  extract_table.py    从 deputy.wat 提取查表
  xcheck_web.mjs      网页 ↔ Python 交叉验证 + 模拟握手
  sync_site.mjs       web/index.html → docs/ 与 apk/www/
  patch_android.mjs   给 Android 工程补蓝牙权限（幂等）
蓝牙热水器开关方案.md    ★ 制作手册（BOM / 接线 / 烧写 / 测试清单 / FAQ / APK 路线）
水控器协议解构.md        原厂协议全解
自研蓝牙热水器方案.md    WLP 阀门版设计
```

## 原厂协议三句话

1. **BLE**：服务 `0xF1F0`，`0xF1F1` 收（手机写），`0xF1F2` 发（设备 notify），20 字节定长帧。
2. **开阀**：连上 → `B0` →（新固件先过 `AE/AF` 认证）→ `B2` 带设备名后 5 位 CRC + 随机数 + 时间 → 设备回 `B2` 表示出水。
3. **结算**：`B3` 关阀，设备在回包最后 3 字节小端给出用水量（0.1 L），费用 = 水量 × 单价。

安全性：整套"加密"只是**混淆**——B2 的校验只依赖广播名里的后 5 位数字，AE/AF 的 4 字节密钥只依赖 nonce + MAC 末两字节（再 XOR 设备名后 4 位），映射表藏在 `deputy.wat` 里靠 WASM 遮掩。拿到算法即可完全复现。

## WSP v1 相对原厂改了什么

| | 原厂 | WSP v1 |
| --- | --- | --- |
| 认证 | 设备名后 4–5 位数字参与运算 | 每台设备 32 字节随机 PSK，`HMAC-SHA256` 挑战应答 |
| 会话密钥 | 无 | `HKDF-SHA256(psk, cnonce‖dnonce, "WSP1-SESSION")` |
| 帧完整性 | 无（或仅校验和） | CRC-16/CCITT + 会话帧 4 字节 MAC |
| 重放 | 无防护 | seq 单调 + dnonce 60 s 过期 |
| 失败处理 | 锁机约 1 小时 | 指数退避，最长 300 s |
| 失效安全 | — | 上电默认断电；超温断电且禁止自动恢复 |
