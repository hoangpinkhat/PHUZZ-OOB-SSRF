# run_all_baseline.ps1
# Runs every baseline compose file sequentially.
# Each target runs for $DefaultMinutes minutes, then stops automatically.
# Logs are saved to ../fuzzer/output-baseline/<config>/
#
# Usage:
#   .\run_all_baseline.ps1              # 15 min per target (default)
#   .\run_all_baseline.ps1 -Minutes 10  # 10 min per target

param(
    [int]$Minutes = 15
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Seconds   = $Minutes * 60

# --- Target list: (compose-file, display-name) ---
$targets = @(
    @{ file = "docker-compose.ssrf-lab.yml";            name = "ssrf-lab"            },
    @{ file = "docker-compose.ssrf-vulnerable-lab.yml"; name = "ssrf-vulnerable-lab" },
    @{ file = "docker-compose.ssrf-xvwa.yml";           name = "xvwa"                },
    @{ file = "docker-compose.pikachu-ssrf.yml";        name = "pikachu"             },
    @{ file = "docker-compose.btslab-ssrf.yml";         name = "btslab"              },
    @{ file = "docker-compose.cve-2020-28975.yml";      name = "CVE-2020-28975"      },
    @{ file = "docker-compose.cve-2021-32682.yml";      name = "CVE-2021-32682"      },
    @{ file = "docker-compose.cve-2023-2249.yml";       name = "CVE-2023-2249"       },
    @{ file = "docker-compose.cve-2020-24148.yml";      name = "CVE-2020-24148"      },
    @{ file = "docker-compose.cve-2020-7071.yml";       name = "CVE-2020-7071"       },
    @{ file = "docker-compose.cve-2022-1751.yml";       name = "CVE-2022-1751"       },
    @{ file = "docker-compose.dvwa-cmdi.yml";           name = "dvwa-cmdi"           },
    @{ file = "docker-compose.bwapp-rfi.yml";           name = "bwapp-rfi"           },
    @{ file = "docker-compose.mutillidae-rfi.yml";      name = "mutillidae-rfi"      }
)

$total = $targets.Count
$i     = 0

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " PHUZZ BASELINE — run all ($total targets, ${Minutes}min each)" -ForegroundColor Cyan
Write-Host " Total estimated time: $([math]::Round($total * $Minutes / 60, 1)) hours" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

foreach ($t in $targets) {
    $i++
    $composeFile = Join-Path $ScriptDir $t.file
    Write-Host "[$i/$total] Starting: $($t.name)" -ForegroundColor Yellow
    Write-Host "  File   : $($t.file)"
    Write-Host "  Runtime: $Minutes min"
    Write-Host "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # --- Cleanup previous stack and stale networks ---
    Write-Host "  Cleaning up previous containers/networks..." -ForegroundColor DarkGray
    try { docker compose -f $composeFile down -v --remove-orphans 2>$null } catch {}
    try { docker network prune -f 2>$null | Out-Null } catch {}
    Start-Sleep -Seconds 3

    # --- Start stack (detached) ---
    Write-Host "  Starting stack..." -ForegroundColor DarkGray
    $startTime = Get-Date
    docker compose -f $composeFile up --build -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [ERROR] Failed to start $($t.name), skipping." -ForegroundColor Red
        continue
    }

    # --- Wait ---
    Write-Host "  Running for $Minutes minutes... (started $($startTime.ToString('HH:mm:ss')))" -ForegroundColor Green
    $deadline = $startTime.AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $remaining = [int]($deadline - (Get-Date)).TotalSeconds
        Write-Host "    $($t.name) — ${remaining}s remaining..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 30
    }

    # --- Stop stack ---
    Write-Host "  Stopping $($t.name)..." -ForegroundColor DarkGray
    docker compose -f $composeFile down -v --remove-orphans
    docker network prune -f | Out-Null

    $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
    Write-Host "  Done: $($t.name) ($elapsed s)`n" -ForegroundColor Green
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ALL BASELINE RUNS COMPLETE" -ForegroundColor Cyan
Write-Host " Results in: code\fuzzer\output-baseline\" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Run TTD analysis:" -ForegroundColor Yellow
Write-Host "  cd d:\phuzz\code"
Write-Host "  python analyze_ttd.py --output-dir fuzzer/output-baseline"
