#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

# Optional: Install sodium (if not already installed)
# brew install libsodium

# 1) Generate -I (collects all directories containing .h under include and src)
mapfile -t INCS < <(find ../../noise_c/include ../../noise_c/src -type f -name '*.h' -exec dirname {} \; | sort -u)
INC_FLAGS=()
for d in "${INCS[@]}"; do INC_FLAGS+=("-I$d"); done
INC_FLAGS+=("-I/usr/local/include")
# 2) Select the .c file to compile (excluding tools/tests/examples, the openssl backend, and the implementation directory included in crypto).
mapfile -t SRCS < <(find ../../noise_c/src -type f -name '*.c' \
  ! -path '*/tools/*' \
  ! -path '*/tests/*' \
  ! -path '*/examples/*' \
  ! -path '*/backend/openssl/*' \
  ! -path '*/crypto/sha2/*' \
  ! -path '*/crypto/chacha/*' \
  ! -path '*/crypto/donna/*' \
)

echo "[INFO] source files: ${#SRCS[@]}"
echo "[INFO] include dirs : ${#INCS[@]}"

# 3) Link oqs + sodium (using sodium backend)
LIB_FLAGS=(-L/usr/local/lib -loqs -lsodium)

# 4) Compile two programs
clang server_pq2.c "${SRCS[@]}" "${INC_FLAGS[@]}" "${LIB_FLAGS[@]}" -o server_pq2
clang client_pq2.c "${SRCS[@]}" "${INC_FLAGS[@]}" "${LIB_FLAGS[@]}" -o client_pq2

echo "[OK] Built -> ./server_pq2  ./client_pq2"
