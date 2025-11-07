#!/usr/bin/env bash
set -euo pipefail
KEM="${1:-Kyber512}"   # 第1参：KEM（可省，默认 Kyber512）
PAT="${2:-NX}"         # 第2参：Noise Pattern（可省，默认 NX）
LABEL="${3:-testrun}"  # 第3参：标签（可省）

# 注意顺序：<PATTERN> <LABEL> [KEM]
./server "$PAT" "$LABEL" "$KEM" &
S=$!
sleep 0.5
./client "$PAT" "$LABEL" "$KEM" || true
kill $S 2>/dev/null || true
wait $S 2>/dev/null || true
