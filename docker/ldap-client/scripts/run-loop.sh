#!/bin/bash
# Запуск всех тестовых скриптов по кругу
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

round=0
while true; do
  round=$((round + 1))
  passed=0
  failed=0
  echo ""
  echo "========== Round $round @ $(date '+%Y-%m-%d %H:%M:%S') =========="
  
  for script in [0-9][0-9]_*.sh; do
    [ -f "$script" ] || continue
    start=$(date +%s.%N)
    if "./$script"; then
      status="OK"
      passed=$((passed + 1))
    else
      status="FAIL"
      failed=$((failed + 1))
    fi
    end=$(date +%s.%N)
    dur=$(awk "BEGIN {printf \"%.2f\", $end - $start}")
    printf "  [%4s] %-25s %5ss\n" "$status" "$script" "$dur"
  done
  
  echo "---------- Round $round: $passed passed, $failed failed ----------"
  sleep 2
done
