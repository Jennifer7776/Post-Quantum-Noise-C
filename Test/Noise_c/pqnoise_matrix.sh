#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/pq_common.sh"

# ========= 可调参数 =========
HOST="127.0.0.1"
PORT=${PORT:-6023}
ITERS=1
WARMUP=0
WHITEBOX=${WHITEBOX:-1}     # 1=开白盒；0=关
SUITE="ChaChaPoly_BLAKE2s"  # 你的实现通常是这个；如需改成 *_SHA256 自行调整
OUTDIR="pq_run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

# 需要测试的模式与KEM（按需删减）
PATTERNS=( NN NX NK XN XK XX KN KK KX IN IK IX )
KEMS=( Kyber512 Kyber768 Bikel1 )

SERVER="./server_pq2"
CLIENT="./client_pq2"

# ========= 前置检查 =========
command -v "$SERVER" >/dev/null 2>&1 || { echo "Can not find $SERVER"; exit 1; }
command -v "$CLIENT" >/dev/null 2>&1 || { echo "Can not find $CLIENT"; exit 1; }

# ========= 汇总结果 =========
SUMMARY_CSV="$OUTDIR/summary.csv"
printf "role,pattern,kem,label,iter,latency_ms,rc\n" > "$SUMMARY_CSV"

# ========= 清理旧进程 =========
kill_on_port "$PORT" || true

# ========= 主循环 =========
total=0; pass=0; fail=0
printf "\n== %s Start Running PQNoise ==\n" "$(ts)"
printf "HOST=%s PORT=%s WHITEBOX=%s\n" "$HOST" "$PORT" "$WHITEBOX"
printf "Log content：%s\n\n" "$OUTDIR"

for kem in "${KEMS[@]}"; do
  for pat in "${PATTERNS[@]}"; do
    total=$((total+1))
    proto="Noise_pq${pat}_${kem}_${SUITE}"
    tag="pq${pat}_${kem}"

    srv_log="$OUTDIR/srv_${tag}.log"
    cli_log="$OUTDIR/cli_${tag}.log"

    # ---- 启动 server ----
    kill_on_port "$PORT" || true
    env PQ_WHITEBOX="$WHITEBOX" "$SERVER" "$pat" demo "$kem" --port "$PORT" \
      >"$srv_log" 2>&1 &
    srv_pid=$!

    if ! wait_port "$PORT" 5; then
      color red "[FAIL] " ; echo "Server failed to start on port $PORT for $proto"
      kill $srv_pid 2>/dev/null || true
      fail=$((fail+1))
      continue
    fi

    # ---- 运行 client ----
    # 说明：client 会打印一行 CSV（和你展示的一样）
    # 我们把标准输出也保存，方便审计
    if env PQ_WHITEBOX="$WHITEBOX" "$CLIENT" "$pat" demo "$kem" \
        --host "$HOST" --port "$PORT" --iters "$ITERS" --warmup "$WARMUP" \
        >"$cli_log" 2>&1; then
      true
    else
      # client 异常退出（也记失败）
      color red "[FAIL] "; echo "$proto client exited with error"
    fi

    # ---- 收尾：关 server ----
    kill $srv_pid 2>/dev/null || true
    sleep 0.1

    # ---- 解析 client 的 CSV 结果行（最后一行以 client, 开头）----
    line=$(grep -E '^client,' "$cli_log" | tail -n1 || true)
    if [[ -z "$line" ]]; then
      # 有的实现先打印表头；我们也兼容 srv 侧的 CSV
      line=$(grep -E '^server,' "$srv_log" | tail -n1 || true)
    fi

    if [[ -n "$line" ]]; then
      # 角色,pattern,kem,label,iter,latency_ms,rc
      role=$(echo "$line" | awk -F',' '{print $1}')
      pattern=$(echo "$line" | awk -F',' '{print $2}')
      kem_name=$(echo "$line" | awk -F',' '{print $3}')
      iter=$(echo "$line" | awk -F',' '{print $5}')
      lat=$(echo "$line" | awk -F',' '{print $6}')
      rc=$(echo "$line" | awk -F',' '{print $7}')
      printf "%s\n" "$line" >> "$SUMMARY_CSV"

      if [[ "$rc" == "0" ]]; then
        pass=$((pass+1))
        color green "[PASS] "
        printf "%-28s " "$proto"
        echo "lat=${lat} ms  rc=0"
      else
        fail=$((fail+1))
        color red "[FAIL] "
        printf "%-28s " "$proto"
        echo "lat=${lat} ms  rc=${rc}"
      fi
    else
      fail=$((fail+1))
      color red "[FAIL] "
      printf "%-28s " "$proto"
      echo "No CSV result line found（Check $cli_log / $srv_log）"
    fi
  done
done

# ========= 汇总结论 =========
printf "\n== %s Test completed ==\n" "$(ts)"
echo "Total combinations: $total  Success: $pass  Failure: $fail"
echo "Summary CSV: $SUMMARY_CSV"
echo "Detailed logs：$OUTDIR/{srv_*.log,cli_*.log}"

if [[ "$fail" -eq 0 ]]; then
  color green "\nConclusion: All handshakes succeeded \n\n"
else
  color yellow "\nConclusion: Some handshakes failed（Check logs for details） ⚠️\n\n"
fi
