#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_kem_full.py — Based on the HQC template, this script generates a new KEM 
backend and registers it across the full PQNoise chain.

"Fixed-naming version":

Regardless of any remaining prefixes in the template (e.g., hqc, kyber, or others), 
all backend function definitions and bindings must be forcibly renamed to a unified pattern:
noise_<alias_nounder>_{keypair, set_keypair_private, set_keypair, validate_public_key, calculate,
 encapsulate, decapsulate}

The constructor must always be named: pqnoise_<alias_c>_new()

The structure name must always be: Noise<Pascal(alias_c)>State

In names.c, append only one new line; in internal.h, insert the definition in the 
designated anchor section; ensure that the dhstate switch cases are correctly linked.
"""

import argparse
import re
import shutil
from pathlib import Path

# pathways
ROOT = Path.cwd()
BACKEND = ROOT / "src" / "backend" / "ref"

INC_CONSTANTS = ROOT / "include" / "noise" / "protocol" / "constants.h"
PROTO_DHSTATE  = ROOT / "src" / "protocol" / "dhstate.c"
PROTO_INTERNAL = ROOT / "src" / "protocol" / "internal.h"
PROTO_NAMES    = ROOT / "src" / "protocol" / "names.c"
PROTO_MKAM     = ROOT / "src" / "protocol" / "Makefile.am"

# internal.h 
INTERNAL_ANCHOR = r"/\*Working here to include PQNoise\*/"

# ---------- Fundation I/O ----------

def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")

def write(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")

def backup(p: Path) -> None:
    if p.exists():
        bak = p.with_suffix(p.suffix + ".bak")
        if not bak.exists():
            shutil.copyfile(p, bak)

# ---------- Normolization ----------

def token(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "", s)

def to_pascal(s: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]", s)
    parts = [p for p in parts if p]
    return "".join(p[:1].upper() + p[1:] for p in parts)

def norm_alias_to_macro(alias: str) -> str:
    """BIKE-L3 / BIKE_L3 -> BIKEL3（NOISE_DH_ 宏 + 显示名）"""
    return re.sub(r"[^A-Za-z0-9]", "", alias).upper()

def alias_to_c_ident(alias: str) -> str:
    """BIKE-L3 / BIKE_L3 -> bike_l3（C 友好，构造器名/文件名用）"""
    s = re.sub(r"[^A-Za-z0-9]", "_", alias).lower()
    s = re.sub(r"_+", "_", s).strip("_")
    return s

def alias_to_symprefix(alias_c: str) -> str:
    """bike_l3 -> bikel3（内部函数前缀：去下划线）"""
    return alias_c.replace("_", "")

# ---------- Rename ----------

FN_SUFFIXES = [
    "keypair",
    "set_keypair_private",
    "set_keypair",
    "validate_public_key",
    "calculate",
    "encapsulate",
    "decapsulate",
]

def force_backend_naming(code: str, alias_symprefix: str) -> str:
    out = code

    # --- A) Process the longer suffix first to avoid it being swallowed up by the shorter suffix ---
    # 1) set_keypair
    pattern_def_set = r"(\bstatic\s+int\s+)([A-Za-z0-9_]+)_set_keypair\s*\("
    repl_def_set    = rf"\1noise_{alias_symprefix}_set_keypair("
    out = re.sub(pattern_def_set, repl_def_set, out)

    # 2) set_keypair_private
    pattern_def_setp = r"(\bstatic\s+int\s+)([A-Za-z0-9_]+)_set_keypair_private\s*\("
    repl_def_setp    = rf"\1noise_{alias_symprefix}_set_keypair_private("
    out = re.sub(pattern_def_setp, repl_def_setp, out)

    #3) Other fixed suffixes will be handled according to the original logic.
    for suf in ["validate_public_key", "calculate", "encapsulate", "decapsulate"]:
        pattern_def = rf"(\bstatic\s+int\s+)([A-Za-z0-9_]+)_{suf}\s*\("
        repl_def    = rf"\1noise_{alias_symprefix}_{suf}("
        out = re.sub(pattern_def, repl_def, out)

    # 4) Finally process keypair, but exclude set_keypair (negative backtracking ensures that the 
    # previous keypair is not 'set_').

    pattern_def_kp = r"(\bstatic\s+int\s+)([A-Za-z0-9_]+)_(?<!set_)keypair\s*\("
    repl_def_kp    = rf"\1noise_{alias_symprefix}_keypair("
    out = re.sub(pattern_def_kp, repl_def_kp, out)

    # B) Function pointer binding: state->parent.<hook> = XXX_<suffix>;
    # Mapping: generate_keypair/keypair; set_keypair_private; set_keypair;
    # validate_public_key; calculate; encaps; decaps

    hook_map = {
        "generate_keypair": "keypair",
        "set_keypair_private": "set_keypair_private",
        "set_keypair": "set_keypair",
        "validate_public_key": "validate_public_key",
        "calculate": "calculate",
        "encaps": "encapsulate",
        "decaps": "decapsulate",
    }
    for hook, suf in hook_map.items():
        pattern_bind = rf"(state->parent\.{hook}\s*=\s*)([a-zA-Z0-9_]+)_{suf}\s*;"
        repl_bind    = rf"\1noise_{alias_symprefix}_{suf};"
        out = re.sub(pattern_bind, repl_bind, out)

    return out

# ---------- Code Generation: Backend Cloning ----------

def gen_backend_file(from_path: Path, alias_c: str, oqs_id: str, alias_macro: str) -> Path:
    """
    Cloning the backend source from the HQC template:
    - Structure name: NoiseHQCState -> Noise<Pascal(alias_c)>State
    - OQS macros: OQS_KEM_alg_* -> OQS_KEM_alg_<oqs_id>
    - Constructor: pqnoise_*_new() -> pqnoise_<alias_c}_new()
    - Clean up template remnants "HQC128" -> alias_macro (e.g., "BIKEL3")
    - Finally, "hard-code naming": force the rewriting of seven static functions bound 
    to the parent pointer as noise_<alias_symprefix>_*
    """
    src = read(from_path)
    alias_symprefix = alias_to_symprefix(alias_c)  # bike_l3 -> bikel3

    # Structure name
    found = sorted(set(re.findall(r"Noise[A-Za-z0-9]+State", src)), key=len, reverse=True)
    old_struct = found[0] if found else "NoiseHQCState"
    new_struct = f"Noise{to_pascal(alias_c)}State"  # e.g., NoiseBikeL3State

    # OQS 
    m = re.search(r"OQS_KEM_alg_[a-z0-9_]+", src)
    old_macro = m.group(0) if m else "OQS_KEM_alg_hqc_128"
    new_macro = f"OQS_KEM_alg_{token(oqs_id.lower())}"

    out = src
    out = out.replace(old_struct, new_struct)
    out = out.replace(old_macro, new_macro)

    # Constructor Name
    out = re.sub(r"\bpqnoise_[a-z0-9_]+_new\s*\(", f"pqnoise_{alias_c}_new(", out)

    # 清模板遗留显示名（如 HQC128）
    out = out.replace("HQC-128", alias_macro)
    out = out.replace("HQC128", alias_macro)

    # Clear legacy display names from templates (e.g., HQC128)
    out = force_backend_naming(out, alias_symprefix)

    # file write
    dst = BACKEND / f"dh-{alias_c}.c"  # eg dh-bike_l3.c
    write(dst, out)
    return dst

# ---------- add code  ----------

def constants_add_define(alias_macro: str) -> str:
    """在 constants.h 追加 #define NOISE_DH_<ALIAS> NOISE_ID('D', n)"""
    if not INC_CONSTANTS.exists():
        raise SystemExit(f"[ERROR] 未找到 {INC_CONSTANTS}")
    txt = read(INC_CONSTANTS)

    # Return the rvalue if it already exists
    if re.search(rf"#define\s+NOISE_DH_{re.escape(alias_macro)}\b", txt):
        m = re.search(rf"#define\s+NOISE_DH_{re.escape(alias_macro)}\s+(NOISE_ID\('[A-Z]',\s*\d+\))", txt)
        return m.group(1) if m else "NOISE_ID('D',0)"

    nums = [int(n) for n in re.findall(r"NOISE_ID\('D',\s*(\d+)\)", txt)]
    next_n = max(nums) + 1 if nums else 8  # If none exist, start from 8
    new_line = f"#define NOISE_DH_{alias_macro}                 NOISE_ID('D', {next_n})   /* Add:{alias_macro} */"

    backup(INC_CONSTANTS)
    last = list(re.finditer(r"#define\s+NOISE_DH_[A-Z0-9_]+\b.*", txt))
    if last:
        idx = last[-1].end()
        txt = txt[:idx] + "\n" + new_line + txt[idx:]
    else:
        txt = txt.rstrip() + "\n" + new_line + "\n"
    write(INC_CONSTANTS, txt)
    return f"NOISE_ID('D', {next_n})"

def internal_add_prototype(alias_c: str) -> None:
    """Insert the new prototype at the end of the anchor paragraph in internal.h; 
    if no anchor is found, append it to the end and add a WARN message."""
    if not PROTO_INTERNAL.exists():
        raise SystemExit(f"[ERROR] 未找到 {PROTO_INTERNAL}")
    proto_line = f"NoiseDHState *pqnoise_{alias_c}_new(void);"
    txt = read(PROTO_INTERNAL)
    if proto_line in txt:
        return

    backup(PROTO_INTERNAL)

    m_anchor = re.search(INTERNAL_ANCHOR, txt)
    if not m_anchor:
        write(PROTO_INTERNAL, txt.rstrip() + "\n" + proto_line + "     /* Add:auto */\n")
        print("[WARN] 未找到 internal.h 锚点，已退化为文件末尾追加。")
        return

    # 从锚点开始匹配连续的原型块
    start = m_anchor.end()
    tail = txt[start:]
    protoline_re = r"[ \t]*NoiseDHState\s*\*pqnoise_[a-zA-Z0-9_]+_new\s*\(void\);\s*(?:/\*.*?\*/)?\s*"
    block_re = re.compile(rf"^(?:{protoline_re}\n)+", re.M)
    m_block = block_re.match(tail)
    insert_pos = start + (m_block.end() if m_block else 0)

    # 插入
    add = ("" if txt[insert_pos-1:insert_pos] == "\n" else "\n") + proto_line + "     /* Add:auto */\n"
    new_txt = txt[:insert_pos] + add + txt[insert_pos:]
    write(PROTO_INTERNAL, new_txt)

def dhstate_add_case(alias_macro: str, alias_c: str) -> None:
    if not PROTO_DHSTATE.exists():
        raise SystemExit(f"[ERROR] 未找到 {PROTO_DHSTATE}")
    case_block = (
        f"    case NOISE_DH_{alias_macro}:\n"
        f"        *state = pqnoise_{alias_c}_new();\n"
        f"        break;\n"
    )
    txt = read(PROTO_DHSTATE)
    if f"case NOISE_DH_{alias_macro}:" in txt:
        return
    backup(PROTO_DHSTATE)
    m = re.search(r"\n\s*default\s*:\s*\n", txt)
    if m:
        pos = m.start()
        txt = txt[:pos] + "\n" + case_block + txt[pos:]
    else:
        txt = txt.rstrip() + "\n" + case_block
    write(PROTO_DHSTATE, txt)

def names_add_mapping(alias_macro: str, alias_text: str) -> None:
    """
    names.c 的 DH 表仅追加一条主命名：
      { NOISE_DH_<ALIAS>, "ALIAS", len }
    """
    if not PROTO_NAMES.exists():
        raise SystemExit(f"[ERROR] 未找到 {PROTO_NAMES}")
    txt = read(PROTO_NAMES)

    entry = f'    {{NOISE_DH_{alias_macro},           "{alias_text}",        {len(alias_text)}}},'
    if entry in txt:
        return

    backup(PROTO_NAMES)
    matches = list(re.finditer(r"^\s*\{\s*NOISE_DH_[A-Z0-9_]+\s*,.*\},\s*$", txt, re.M))
    insert_at = matches[-1].end() if matches else len(txt)
    new_txt = txt[:insert_at] + "\n" + entry + txt[insert_at:]
    write(PROTO_NAMES, new_txt)

def mkam_add_source(new_backend_path: Path) -> None:
    if not PROTO_MKAM.exists():
        print("[WARN] 未找到 src/protocol/Makefile.am（若用 CMake 请手动把新源加入 target）")
        return
    rel = f"../backend/ref/{new_backend_path.name}"
    txt = read(PROTO_MKAM)
    if rel in txt:
        return
    backup(PROTO_MKAM)
    m = re.search(r"(libnoise[^\n]*?_SOURCES\s*=\s*.*?)(\n[^ \t])", txt, re.S)
    if m:
        block = m.group(1)
        txt = txt.replace(block, block + f" \\\n\t{rel}")
    else:
        txt = txt.rstrip() + f"\n# add_kem_full.py: please include {rel} into *_SOURCES\n"
    write(PROTO_MKAM, txt)

# ---------- Main ----------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-file", default=str(BACKEND / "dh-hqc.c"),
                    help="模板后端源文件（默认 src/backend/ref/dh-hqc.c）")
    ap.add_argument("--new-alias", required=True, help="展示别名（如 BIKE-L3 / BIKE_L3）")
    ap.add_argument("--new-oqs-id", required=True, help="liboqs 算法 ID（如 bike_l3）")
    ap.add_argument("--new-prefix", required=False, default="",
                    help="兼容旧参数（已忽略）")
    args = ap.parse_args()

    from_path = Path(args.from_file)
    if not from_path.exists():
        raise SystemExit(f"模板不存在: {from_path}")

    # Normalized
    alias_macro = norm_alias_to_macro(args.new_alias)   # e.g., BIKEL3
    alias_text  = alias_macro
    alias_c     = alias_to_c_ident(args.new_alias)     # e.g., bike_l3

    # 1) Create backend
    new_backend = gen_backend_file(from_path, alias_c, args.new_oqs_id, alias_macro)
    print(f"[OK ] backend: {new_backend}")

    # 2) constants.h
    noise_id_rhs = constants_add_define(alias_macro)
    print(f"[OK ] constants.h: #define NOISE_DH_{alias_macro} {noise_id_rhs}")

    # 3) internal.h
    internal_add_prototype(alias_c)
    print(f"[OK ] internal.h: prototype pqnoise_{alias_c}_new")

    # 4) dhstate.c
    dhstate_add_case(alias_macro, alias_c)
    print(f"[OK ] dhstate.c: case NOISE_DH_{alias_macro}")

    # 5) names.c
    names_add_mapping(alias_macro, alias_text)
    print(f"[OK ] names.c: map NOISE_DH_{alias_macro} -> \"{alias_text}\"")

    # 6) Makefile.am
    mkam_add_source(new_backend)
    print(f"[OK ] Makefile.am: add {new_backend.name}")

if __name__ == "__main__":
    main()
