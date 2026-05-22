#!/bin/bash
# run_all_baseline.sh
# Runs every baseline compose file sequentially.
# Each target runs for MINUTES minutes, then stops automatically.
# Logs are saved to ../fuzzer/output-baseline/<config>/
#
# Usage:
#   ./run_all_baseline.sh           # 15 min per target (default)
#   ./run_all_baseline.sh 10        # 10 min per target

MINUTES=${1:-15}
SECONDS_RUN=$((MINUTES * 60))
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

declare -a FILES=(
    "docker-compose.ssrf-lab.yml|ssrf-lab"
    "docker-compose.ssrf-vulnerable-lab.yml|ssrf-vulnerable-lab"
    "docker-compose.ssrf-xvwa.yml|xvwa"
    "docker-compose.pikachu-ssrf.yml|pikachu"
    "docker-compose.btslab-ssrf.yml|btslab"
    "docker-compose.cve-2020-28975.yml|CVE-2020-28975"
    "docker-compose.cve-2021-32682.yml|CVE-2021-32682"
    "docker-compose.cve-2023-2249.yml|CVE-2023-2249"
    "docker-compose.cve-2020-24148.yml|CVE-2020-24148"
    "docker-compose.cve-2020-7071.yml|CVE-2020-7071"
    "docker-compose.cve-2022-1751.yml|CVE-2022-1751"
    "docker-compose.dvwa-cmdi.yml|dvwa-cmdi"
    "docker-compose.bwapp-rfi.yml|bwapp-rfi"
    "docker-compose.mutillidae-rfi.yml|mutillidae-rfi"
)

TOTAL=${#FILES[@]}
ESTIMATED=$(echo "scale=1; $TOTAL * $MINUTES / 60" | bc)

echo "========================================"
echo " PHUZZ BASELINE — run all ($TOTAL targets, ${MINUTES}min each)"
echo " Total estimated time: ${ESTIMATED} hours"
echo "========================================"
echo ""

i=0
for entry in "${FILES[@]}"; do
    FILE="${entry%%|*}"
    NAME="${entry##*|}"
    i=$((i + 1))
    COMPOSE_FILE="$SCRIPT_DIR/$FILE"

    echo "[$i/$TOTAL] Starting: $NAME"
    echo "  File   : $FILE"
    echo "  Runtime: $MINUTES min"
    echo "  Time   : $(date '+%Y-%m-%d %H:%M:%S')"

    # Cleanup previous stack and stale networks
    echo "  Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    docker network prune -f > /dev/null 2>&1 || true
    sleep 3

    # Start stack (detached)
    echo "  Starting stack..."
    docker compose -f "$COMPOSE_FILE" up --build -d
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Failed to start $NAME, skipping."
        continue
    fi

    START_TS=$(date +%s)
    DEADLINE=$((START_TS + SECONDS_RUN))

    echo "  Running for $MINUTES minutes... (started $(date '+%H:%M:%S'))"
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        REMAINING=$((DEADLINE - $(date +%s)))
        echo "    $NAME — ${REMAINING}s remaining..."
        sleep 30
    done

    # Stop stack
    echo "  Stopping $NAME..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
    docker network prune -f > /dev/null 2>&1 || true

    ELAPSED=$(( $(date +%s) - START_TS ))
    echo "  Done: $NAME (${ELAPSED}s)"
    echo ""
done

echo "========================================"
echo " ALL BASELINE RUNS COMPLETE"
echo " Results in: code/fuzzer/output-baseline/"
echo "========================================"
echo ""
echo "Run TTD analysis:"
echo "  cd /mnt/d/phuzz/code"
echo "  python analyze_ttd.py --output-dir fuzzer/output-baseline"
