# ==== PQ_Noise2.0/Test/Noise_c/Makefile ====
CC ?= clang
NOISE_ROOT := ../../noise_c

# 统一收集头文件目录（自动生成 -I，保证 internal.h/crypto/* 能找到）
INC_FLAGS := $(shell find $(NOISE_ROOT)/include $(NOISE_ROOT)/src -type f -name '*.h' -exec dirname {} \; | sort -u | sed -e 's/^/-I/g')
INC_FLAGS += -I/usr/local/include

# ---- 仅选用需要的源，避免重复实现/缺失文件 ----

# 1) 核心协议层
SRCS_PROTOCOL := $(shell find $(NOISE_ROOT)/src/protocol -maxdepth 1 -type f -name '*.c')

# 2) sodium 后端（提供 chacha/poly、aesgcm、hashes、x25519、ed25519 等）
SRCS_SODIUM   := $(shell find $(NOISE_ROOT)/src/backend/sodium -maxdepth 1 -type f -name '*.c')

# 3) PQ KEM（ref 实现）：kyber/hqc/bike
SRCS_PQREF    := $(NOISE_ROOT)/src/backend/ref/dh-kyber.c \
                 $(wildcard $(NOISE_ROOT)/src/backend/ref/dh-hqc*.c) \
                 $(wildcard $(NOISE_ROOT)/src/backend/ref/dh-bike_l*.c)

# 4) 本地 crypto 基元（只挑用得到的；不要 newhope/curve448/goldilocks/ed25519测试/fuzz/donna）
SRCS_CRYPTO   := \
  $(NOISE_ROOT)/src/crypto/aes/rijndael-alg-fst.c \
  $(NOISE_ROOT)/src/crypto/blake2/blake2b.c \
  $(NOISE_ROOT)/src/crypto/blake2/blake2s.c \
  $(NOISE_ROOT)/src/crypto/chacha/chacha.c \
  $(NOISE_ROOT)/src/crypto/ghash/ghash.c \
  $(NOISE_ROOT)/src/crypto/sha2/sha256.c \
  $(NOISE_ROOT)/src/crypto/sha2/sha512.c

# 5) 其他必要模块
SRCS_KEYS     := $(shell find $(NOISE_ROOT)/src/keys -maxdepth 1 -type f -name '*.c')
SRCS_PROTOBUF := $(shell find $(NOISE_ROOT)/src/protobufs -maxdepth 1 -type f -name '*.c')

# 合并所有源
SRC_FILES := $(SRCS_PROTOCOL) $(SRCS_SODIUM) $(SRCS_PQREF) $(SRCS_CRYPTO) $(SRCS_KEYS) $(SRCS_PROTOBUF)

# 链接库：OQS + Sodium（sodium 后端需要）
LIBS := -L/usr/local/lib -loqs -lsodium
CFLAGS := -O2 -Wall -Wextra $(INC_FLAGS)

all: server_pq2 client_pq2

server_pq2: server_pq2.c
	$(CC) $(CFLAGS) $(SRC_FILES) $< -o $@ $(LIBS)

client_pq2: client_pq2.c
	$(CC) $(CFLAGS) $(SRC_FILES) $< -o $@ $(LIBS)

clean:
	rm -f server_pq2 client_pq2
# ==== end ====
