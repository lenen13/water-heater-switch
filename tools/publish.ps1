# 一键发布到 GitHub：建仓库 → 上传全部文件 → 打开 Pages → 触发 APK 编译
#
# 用法（在 waterctl 目录下）：
#   pwsh -File tools/publish.ps1                 # 交互式，会让你粘 token
#   pwsh -File tools/publish.ps1 -DryRun         # 只列出会上传哪些文件
#   pwsh -File tools/publish.ps1 -Token ghp_xxx -RepoName water-heater-switch
#
# 需要的 token 权限（classic token）：repo + workflow
# 生成地址：https://github.com/settings/tokens
[CmdletBinding()]
param(
  [string]$Token,
  [string]$RepoName = 'water-heater-switch',
  [string]$Root = '',
  [switch]$DryRun
)

if (-not $Root -and $PSScriptRoot) { $Root = Split-Path -Parent $PSScriptRoot }
if (-not $Root) { $Root = (Get-Location).Path }
$Root = (Resolve-Path -LiteralPath $Root).Path

$ErrorActionPreference = 'Stop'
$api = 'https://api.github.com'

# Windows PowerShell 5.1 默认可能用 TLS 1.0，接 GitHub API 会失败
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# ---------- 1. 收集要上传的文件 ----------
$dirs = @('docs', 'web', 'firmware', 'py', 'tools', '.github', 'apk')
$rootFiles = @('README.md', '蓝牙热水器开关方案.md', '水控器协议解构.md', '自研蓝牙热水器方案.md', '.gitignore')

$skipDirs = @('node_modules', '__pycache__', 'android', '.gradle', '.git', '.pio', 'build')
$files = New-Object System.Collections.Generic.List[object]

function Add-File([string]$full, [string]$rel) {
  $files.Add([pscustomobject]@{
      Full = $full
      Rel  = ($rel -replace '\\', '/')
      Size = (Get-Item -LiteralPath $full).Length
    })
}

foreach ($f in $rootFiles) {
  $p = Join-Path $Root $f
  if (Test-Path -LiteralPath $p) { Add-File $p $f } else { Write-Warning "缺少 $f" }
}

foreach ($d in $dirs) {
  $base = Join-Path $Root $d
  if (-not (Test-Path -LiteralPath $base)) { Write-Warning "缺少目录 $d"; continue }
  Get-ChildItem -LiteralPath $base -Recurse -File -Force | ForEach-Object {
    $parts = $_.FullName.Substring($Root.Length + 1) -split '[\\/]'
    if ($parts | Where-Object { $skipDirs -contains $_ }) { return }
    if ($_.Extension -eq '.pyc') { return }
    Add-File $_.FullName $_.FullName.Substring($Root.Length + 1)
  }
}

$totalBytes = ($files | Measure-Object Size -Sum).Sum
Write-Host ("→ 待上传 {0} 个文件，共 {1:N0} 字节" -f $files.Count, $totalBytes) -ForegroundColor Cyan
$files | Sort-Object Rel | ForEach-Object { Write-Host ("   {0,-42} {1,8}" -f $_.Rel, $_.Size) }

if ($DryRun) {
  Write-Host "`n[dry-run] 没有访问网络，参数与文件清单正常。" -ForegroundColor Yellow
  return
}

# ---------- 2. 拿 token ----------
# 说明：不用 Read-Host -AsSecureString —— Windows PowerShell 5.1 的控制台里往
# 安全输入框粘贴很容易把 Ctrl+V 变成字面量 "^V"，导致 token 变成乱码（表现为 401）。
# 改成：先读剪贴板；读不到再明文输入。
if (-not $Token) {
  $clip = ''
  try { $clip = [string](Get-Clipboard -Raw) } catch { }
  $clip = $clip.Trim()
  if ($clip -match '^(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})$') {
    $Token = $clip
    Write-Host '→ 已从剪贴板读到 token' -ForegroundColor Green
  } elseif ($clip.Length -gt 0) {
    Write-Host ("→ 剪贴板里不是 token（开头是：{0}…），改为手动输入" -f $clip.Substring(0, [Math]::Min(12, $clip.Length))) -ForegroundColor Yellow
  }
}
if (-not $Token) {
  $Token = Read-Host '粘贴 GitHub Token（会显示在屏幕上，不会保存）'
}
$Token = $Token.Trim()
if ($Token -notmatch '^(gh[pousr]_|github_pat_)') {
  Write-Host ''
  Write-Host '这串字符不像 GitHub token：' -ForegroundColor Red
  Write-Host ("  你输入的是：{0}…（{1} 个字符）" -f $Token.Substring(0, [Math]::Min(8, $Token.Length)), $Token.Length) -ForegroundColor Red
  Write-Host '  正常情况下应该是 ghp_ 开头、总共 40 个字符。' -ForegroundColor Red
  Write-Host '  如果你粘的是账号密码、验证码、或者网页上的其他东西，会得到 401 未授权。' -ForegroundColor Red
  throw 'token 格式不对，已停止'
}

$headers = @{
  Authorization          = "token $Token"
  Accept                 = 'application/vnd.github+json'
  'User-Agent'           = 'wsp-publish-script'
  'X-GitHub-Api-Version' = '2022-11-28'
}

function Invoke-GH {
  param([string]$Method, [string]$Path, $Body)
  $p = @{ Method = $Method; Uri = "$api$Path"; Headers = $headers }
  if ($null -ne $Body) {
    $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
    $p.ContentType = 'application/json; charset=utf-8'
  }
  Invoke-RestMethod @p
}

# ---------- 3. 谁在登录 ----------
try {
  $me = Invoke-GH GET '/user'
} catch {
  Write-Host ''
  Write-Host 'GitHub 拒绝了这枚 token（401 未授权）。常见原因：' -ForegroundColor Red
  Write-Host '  1) 复制时漏字符 / 多空格 —— 重新复制一次（用「Copy」按钮，不要手选）' -ForegroundColor Red
  Write-Host '  2) 生成后又被删掉或过期了 —— 去 https://github.com/settings/tokens 看是否还在' -ForegroundColor Red
  Write-Host '  3) 用的是账号密码 —— 必须是 Personal access token（ghp_ 开头）' -ForegroundColor Red
  throw "token 无效：$($_.Exception.Message)"
}
$owner = $me.login
Write-Host "→ 已认证：$owner" -ForegroundColor Green

# ---------- 4. 建仓库（已存在就复用）----------
$repoExists = $false
try {
  $repo = Invoke-GH GET "/repos/$owner/$RepoName"
  $repoExists = $true
  Write-Host "→ 仓库已存在：$($repo.html_url)（继续往里传文件）" -ForegroundColor Yellow
} catch {
  try {
    $repo = Invoke-GH POST '/user/repos' @{
      name        = $RepoName
      description = '蓝牙热水器开关：ESP32-C3 + WSP 协议 + 网页/APK 控制'
      private     = $false
      auto_init   = $false
      has_issues  = $true
    }
    Write-Host "→ 已创建仓库：$($repo.html_url)" -ForegroundColor Green
  } catch {
    throw "创建仓库失败：$($_.Exception.Message)"
  }
}

# ---------- 5. 逐文件上传 ----------
$i = 0
$failed = @()
foreach ($f in $files) {
  $i++
  $enc = ([uri]::EscapeDataString($f.Rel)) -replace '%2F', '/'
  $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.Full))
  $body = @{ message = "add $($f.Rel)"; content = $b64; branch = 'main' }
  try {
    Invoke-GH PUT "/repos/$owner/$RepoName/contents/$enc" $body | Out-Null
  } catch {
    # 文件已存在时需要带上 sha 才能覆盖
    try {
      $old = Invoke-GH GET "/repos/$owner/$RepoName/contents/$enc`?ref=main"
      $body.sha = $old.sha
      Invoke-GH PUT "/repos/$owner/$RepoName/contents/$enc" $body | Out-Null
    } catch {
      $failed += $f.Rel
      Write-Warning "上传失败 $($f.Rel)：$($_.Exception.Message)"
    }
  }
  Write-Progress -Activity '上传文件' -Status "$i / $($files.Count)  $($f.Rel)" -PercentComplete ($i * 100 / $files.Count)
}
Write-Progress -Activity '上传文件' -Completed

# ---------- 6. 打开 GitHub Pages（main / docs）----------
$pagesUrl = "https://$owner.github.io/$RepoName/"
try {
  Invoke-GH POST "/repos/$owner/$RepoName/pages" @{ source = @{ branch = 'main'; path = '/docs' } } | Out-Null
  Write-Host "→ 已打开 GitHub Pages（main /docs）" -ForegroundColor Green
} catch {
  try {
    Invoke-GH PUT "/repos/$owner/$RepoName/pages" @{ source = @{ branch = 'main'; path = '/docs' } } | Out-Null
    Write-Host "→ Pages 之前已开，已更新为 main /docs" -ForegroundColor Green
  } catch {
    Write-Warning "自动开 Pages 失败（可能 token 缺 repo 权限，或仓库还没初始化完）：$($_.Exception.Message)"
    Write-Host "  可以手动开：仓库 → Settings → Pages → main + /docs" -ForegroundColor Yellow
  }
}

# ---------- 7. 触发 APK 云端编译 ----------
try {
  Invoke-GH POST "/repos/$owner/$RepoName/actions/workflows/build-apk.yml/dispatches" @{ ref = 'main' } | Out-Null
  Write-Host "→ 已触发 APK 编译" -ForegroundColor Green
} catch {
  Write-Warning "触发 APK 编译失败（大概 token 缺 workflow 权限）：$($_.Exception.Message)"
  Write-Host "  可以手动跑：仓库 → Actions → build-apk → Run workflow" -ForegroundColor Yellow
}

# ---------- 8. 结果 ----------
Write-Host ''
Write-Host '================ 完成 ================' -ForegroundColor Cyan
Write-Host "仓库      : $($repo.html_url)"
Write-Host "网页版    : $pagesUrl   （Pages 首次生效要等 1-2 分钟）"
Write-Host "APK 编译  : $($repo.html_url)/actions"
if ($failed.Count) {
  Write-Host "失败文件  : $($failed -join ', ')" -ForegroundColor Red
}
Write-Host '======================================'
