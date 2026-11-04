#Requires -Version 5.1
<#
AI-SafeGuard Windows 平滑升级（在旧版本已装服务的基础上换到新版本）。

用法（管理员 PowerShell）：
  powershell -ExecutionPolicy Bypass -File scripts\upgrade-windows.ps1 `
      -Package .\aisafeguard-windows-x64.zip -BackupData

参数：
  -Package     新版本 zip（或直接给 aisafeguard.exe）；zip 同目录有 .sha256 时会先校验
  -InstallDir  安装目录，默认 %ProgramFiles%\AISafeGuard（服务固定从这里运行）
  -BackupData  升级前把 %ProgramData%\aisafeguard 复制到安装目录 backup\ 下
  -DryRun      只打印计划，不做任何改动（无需管理员）

流程：校验包 → 停服务 → 备份旧 exe → 复制新 exe → 重建服务 → 启动 → 等运行态；
任一步失败自动回滚到旧二进制。数据目录不动，首次启动自动迁移数据库。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Package,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AISafeGuard'),
    [switch]$BackupData,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AISafeGuard'
$dataDir = Join-Path $env:ProgramData 'aisafeguard'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Svc {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
}

function Wait-SvcState([string]$state, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $s = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $s) { return ($state -eq 'Gone') }
        if ($s.Status -eq $state) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

if (-not (Test-Path $Package)) { throw "找不到升级包: $Package" }
if (-not $DryRun -and -not (Test-Admin)) {
    throw '需要管理员权限：请以管理员身份打开 PowerShell 后重试（或用 -DryRun 先看计划）。'
}

# ---------- 1) 解开升级包 + 校验 ----------
$work = Join-Path $env:TEMP ("aisafeguard-upgrade-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $newExe = $null
    if ($Package -match '\.zip$') {
        $shaFile = "$Package.sha256"
        if (Test-Path $shaFile) {
            $want = ((Get-Content $shaFile -TotalCount 1) -split '\s+')[0].ToLower()
            $got = (Get-FileHash $Package -Algorithm SHA256).Hash.ToLower()
            if ($want -ne $got) { throw "sha256 校验失败: 期望 $want，实际 $got" }
            Write-Host '[1/6] sha256 校验通过' -ForegroundColor Green
        } else {
            Write-Warning "未找到 $shaFile，跳过升级包校验"
        }
        Expand-Archive -Path $Package -DestinationPath $work -Force
        $newExe = Get-ChildItem $work -Recurse -Filter 'aisafeguard.exe' |
            Select-Object -First 1 -ExpandProperty FullName
    } else {
        $newExe = (Resolve-Path $Package).Path
    }
    if (-not $newExe) { throw '升级包里没有 aisafeguard.exe' }
    $newVer = (& $newExe --version | Select-Object -First 1)
    Write-Host "[2/6] 升级包: $newVer"

    # ---------- 2) 现状 ----------
    $svc = Get-Svc
    $oldPath = $null
    $targetExe = Join-Path $InstallDir 'aisafeguard.exe'
    if ($svc) {
        $oldPath = $svc.PathName
        Write-Host "[3/6] 现有服务: $($svc.State)，当前二进制: $oldPath"
    } else {
        Write-Host '[3/6] 未检测到已安装服务（按全新安装处理）'
    }
    Write-Host "[4/6] 安装目标: $targetExe"

    if ($DryRun) {
        Write-Host '[DryRun] 将执行：停服务 → 备份旧 exe → 复制新 exe → 重建服务 → 启动 → 等待运行态' -ForegroundColor Yellow
        if ($BackupData) { Write-Host "[DryRun] 将备份数据目录: $dataDir" -ForegroundColor Yellow }
        return
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $backup = $null
    if ($BackupData -and (Test-Path $dataDir)) {
        $dst = Join-Path $InstallDir ('backup\data-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Write-Host "  备份数据目录 → $dst"
        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
        Copy-Item $dataDir $dst -Recurse -Force
    }

    try {
        if ($svc) {
            Write-Host '[5/6] 停止并移除旧服务...'
            & sc.exe stop $serviceName | Out-Null
            if (-not (Wait-SvcState 'Stopped' 60)) { throw '服务停止超时' }
            # 备份旧二进制（服务路径可能是 "路径" 加参数，取第一个引号/空格前段）
            if ($oldPath) {
                $oldExe = $oldPath
                if ($oldExe.StartsWith('"')) { $oldExe = $oldExe.Substring(1).Split('"')[0] }
                else { $oldExe = $oldExe.Split(' ')[0] }
                if (Test-Path $oldExe) {
                    $bkDir = Join-Path $InstallDir 'backup'
                    New-Item -ItemType Directory -Force -Path $bkDir | Out-Null
                    $backup = Join-Path $bkDir ('aisafeguard-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.exe')
                    Copy-Item $oldExe $backup -Force
                    Write-Host "  旧二进制备份: $backup"
                }
            }
            & sc.exe delete $serviceName | Out-Null
            if (-not (Wait-SvcState 'Gone' 15)) { Write-Warning '服务删除仍在等待，继续尝试安装' }
        }

        Copy-Item $newExe $targetExe -Force
        Write-Host "  已复制到 $targetExe"

        Push-Location $InstallDir
        try {
            $installed = $false
            for ($i = 0; $i -lt 3 -and -not $installed; $i++) {
                & $targetExe service install | Out-Null
                $installed = $true
            }
            & $targetExe service start | Out-Null
        } finally {
            Pop-Location
        }

        if (-not (Wait-SvcState 'Running' 90)) {
            throw '服务启动超时（首次启动要迁移数据库；可稍后用事件查看器看 AISafeGuard 服务日志）'
        }
        Write-Host '[6/6] 服务已运行' -ForegroundColor Green
        Write-Host "  目标版本: $newVer"
        Write-Host '  现在用普通权限启动 GUI 即可（会自动连接服务，侧栏版本应与上面一致）'
    } catch {
        Write-Warning "升级失败: $($_.Exception.Message)"
        if ($backup -and (Test-Path $backup)) {
            Write-Warning "回滚到旧二进制: $backup"
            & sc.exe stop $serviceName 2>$null | Out-Null
            Start-Sleep -Seconds 2
            & sc.exe delete $serviceName 2>$null | Out-Null
            Start-Sleep -Seconds 2
            Copy-Item $backup $targetExe -Force
            Push-Location $InstallDir
            try {
                & $targetExe service install | Out-Null
                & $targetExe service start | Out-Null
            } finally {
                Pop-Location
            }
            Write-Warning '已回滚（服务已用旧二进制重新注册）'
        } else {
            Write-Warning '没有可回滚的旧二进制；数据目录未受影响'
        }
        throw
    }
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
