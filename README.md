
# PQNoise-C: A Lightweight Post-Quantum Noise Framework

PQNoise-C is a C-language implementation of a hybrid post-quantum handshake framework based on the [Noise Protocol Framework](https://noiseprotocol.org).  
It replaces Diffie–Hellman key exchanges with post-quantum KEMs such as Kyber and BIKE, while preserving protocol semantics and message flow.

---

###  Structure

- **`noise_c/`** – Core implementation of PQNoise-C, extending Noise-C with PQ KEM integration,  
  EKEM/SKEM token registration, and MixKey/MixHash sequence handling.

- **`Test/`** – Test suite and experimental logs for handshake verification (`rc==0`, `Split()`),  
  performance evaluation, and result recording.

---


##  Features
- Integrated **EKEM/SKEM tokens** for post-quantum handshakes  
- Supports **Kyber512 / Kyber768 / BIKE-L1**  
- Fully compatible with 12 standard Noise handshake patterns  
- Modular KEM backend with simple registration scripts  
- Verified semantic consistency via MixHash/MixKey order tracing  

---



##  Build
```bash
git clone https://github.com/Jennifer7776/Post-Quantum-Noise-C.git
cd Post-Quantum-Noise-C/noise_c
mkdir build && cd build
cmake ..
make
