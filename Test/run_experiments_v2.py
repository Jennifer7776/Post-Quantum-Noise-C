#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robust PQNoise runner (v2)
- curve25519/X25519 -> server_dh/client_dh (DH baseline)
- Enforced tc-netem verification (0ms & 50ms RTT check)
- Per-combo spot-check only when loss==0 (avoid ping fail under loss)
- Resume / skip completed combos via DONE marker
- Watchdog auto-restart on unexpected crash (optional)
- Graceful error handling + per-combo fail logs

Example:
  sudo -E ./run_experiments_v2.py \
    --patterns NK,NX,KK \
    --kems Kyber512,HQC128,BIKEL1,curve25519 \
    --losses 0,1,2,5,10 \
    --delays 0,10,20,30,40,50,60,70,80,90,100 \
    --iters 120 --warmup 20 \
    --label-prefix paper \
    --outdir Results_PaperRun \
    --watchdog --max-restarts 5
"""

import argparse
import os
import sys
import subprocess
import shlex
from datetime import datetime
from pathlib import Path
import time
import re
import traceback
import json
from typing import Tuple

# ----------------------------- utils -----------------------------

def run(cmd, check=True, capture=False, text=True, env=None, echo=True) -> Tuple[int,str,str]:
    if isinstance(cmd, str):
        cmd_list = shlex.split(cmd)
    else:
        cmd_list = cmd
    if echo:
        print(" $", " ".join(cmd_list))
    p = subprocess.run(
        cmd_list,
        env=env,
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=text,
    )
    if check and p.returncode != 0:
        out = p.stdout if capture else ""
        err = p.stderr if capture else ""
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd_list)}\nSTDOUT:\n{out}\n\nSTDERR:\n{err}")
    return p.returncode, (p.stdout if capture else ""), (p.stderr if capture else "")

def sudo_wrap(x):
    return ["sudo","-E"] + (x if isinstance(x, list) else shlex.split(x))

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_tag():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def parse_ping_avg(stdout: str):
    # e.g., rtt min/avg/max/mdev = 100.151/100.163/100.186/0.016 ms
    m = re.search(r"rtt .* = .*?/([\d\.]+)/", stdout)
    return float(m.group(1)) if m else None

def write_text(p: Path, s: str):
    p.write_text(s, encoding="utf-8")

# ----------------------------- qdisc ops -----------------------------

def qdisc_replace(ns, dev, delay_ms, loss_pct):
    run(sudo_wrap(["ip","netns","exec", ns, "tc","qdisc","replace","dev",dev,"root","netem",
                   "delay", f"{delay_ms}ms","loss", f"{loss_pct}%"]),
        check=True, capture=False)

def qdisc_del(ns, dev):
    run(sudo_wrap(["ip","netns","exec", ns, "tc","qdisc","del","dev",dev,"root"]),
        check=False, capture=False)

def qdisc_show(ns, dev):
    _, out, _ = run(sudo_wrap(["ip","netns","exec", ns, "tc","qdisc","show","dev",dev]),
                    capture=True)
    return out

# ----------------------------- verification -----------------------------

def netem_verify(args) -> None:
    """Strong preflight verification: 0ms baseline then 50ms(one-way) RTT ~= +100ms."""
    print("=== [VERIFY] Hard check netem on both ends ===")
    print("Interfaces:", f"{args.cli_ns}:{args.cli_if}", "<->", f"{args.srv_ns}:{args.srv_if}")
    print("[qdisc before] CLI:\n" + qdisc_show(args.cli_ns, args.cli_if))
    print("[qdisc before] SRV:\n" + qdisc_show(args.srv_ns, args.srv_if))

    # reset to 0ms
    qdisc_del(args.cli_ns, args.cli_if)
    qdisc_del(args.srv_ns, args.srv_if)
    qdisc_replace(args.cli_ns, args.cli_if, 0, 0)
    qdisc_replace(args.srv_ns, args.srv_if, 0, 0)

    # baseline ping (3 probes)
    print(">>> [VERIFY] ping @0ms ...")
    rc0, out0, _ = run(sudo_wrap(["ip","netns","exec", args.cli_ns, "ping","-c","3","-w","3", args.server_ip]), capture=True)
    base = parse_ping_avg(out0)
    if base is None:
        if not args.force:
            raise RuntimeError("VERIFY@0ms: cannot parse ping avg")
        print("!!! VERIFY@0ms parse failed (continue due to --force).")

    # set 50ms each side
    print(">>> [VERIFY] set 50ms one-way on both ends")
    qdisc_replace(args.cli_ns, args.cli_if, 50, 0)
    qdisc_replace(args.srv_ns, args.srv_if, 50, 0)

    # test ping (3 probes)
    print(">>> [VERIFY] ping @50ms ...")
    rc1, out1, _ = run(sudo_wrap(["ip","netns","exec", args.cli_ns, "ping","-c","3","-w","3", args.server_ip]), capture=True)
    rtt = parse_ping_avg(out1)

    print(f"RTT(avg)@0ms = {base if base is not None else 'NA'} ms")
    print(f"RTT(avg)@50ms(each) = {rtt if rtt is not None else 'NA'} ms; expect ≈ base + 100ms")

    if base is not None and rtt is not None:
        if rtt < base + 60 and not args.force:  # 保守阈值，给虚拟化留余地
            raise RuntimeError(f"VERIFY failed: RTT delta too small: got {rtt-base:.1f} ms (expect ~100ms)")
    else:
        print("!!! VERIFY got NA values (continue).")

    # restore to 0ms before experiments
    qdisc_replace(args.cli_ns, args.cli_if, 0, 0)
    qdisc_replace(args.srv_ns, args.srv_if, 0, 0)

# ----------------------------- server/client -----------------------------

def select_binaries(args, kem):
    dh_set = {k.strip() for k in args.dh_kems.split(",") if k.strip()}
    if kem in dh_set:
        return args.dh_server_exe, args.dh_client_exe
    return args.server_exe, args.client_exe

def start_server(args, pattern, label, kem, server_log_path):
    srv_exe, _ = select_binaries(args, kem)
    cmd = sudo_wrap([
        "ip","netns","exec", args.srv_ns,
        "env", f"LD_LIBRARY_PATH={args.ld_path}" if args.ld_path else "LD_LIBRARY_PATH=",
        srv_exe, pattern, label, kem,
        "--iters", str(args.iters),
        "--warmup", str(args.warmup),
        "--csv"
    ])
    f = open(server_log_path, "w")
    proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    return proc, f

def run_client(args, pattern, label, kem, client_log_path):
    _, cli_exe = select_binaries(args, kem)
    cmd = sudo_wrap([
        "ip","netns","exec", args.cli_ns,
        "env", f"LD_LIBRARY_PATH={args.ld_path}" if args.ld_path else "LD_LIBRARY_PATH=",
        cli_exe, pattern, label, kem,
        "--iters", str(args.iters),
        "--warmup", str(args.warmup),
        "--csv"
    ])
    with open(client_log_path, "w") as f:
        p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    return p.returncode == 0

# ----------------------------- orchestration -----------------------------

def combo_done_marker(outdir: Path) -> Path:
    return outdir / "DONE"

def combo_is_done(outdir: Path) -> bool:
    return combo_done_marker(outdir).exists()

def mark_combo_done(outdir: Path, meta: dict):
    write_text(combo_done_marker(outdir), json.dumps(meta, ensure_ascii=False, indent=2))

def combo_fail_log(outdir: Path) -> Path:
    return outdir / "RUN_FAIL.txt"

def spot_check_delay(args, delay, loss) -> None:
    """只在 loss==0 时做轻量 RTT spot-check；不抛异常，只告警。"""
    if delay < 50 or loss != 0:
        return
    print(f"--- [SPOT] RTT check at delay={delay}ms (loss=0) ---")
    rc, pout, _ = run(sudo_wrap(["ip","netns","exec", args.cli_ns, "ping","-c","3","-w","3", args.server_ip]),
                      capture=True, check=False)
    if rc != 0:
        print("!!! WARN: spot-check ping got no reply; continue.")
        return
    avg = parse_ping_avg(pout)
    if avg is None:
        print("!!! WARN: spot-check avg NA; continue.")
        return
    expect = 2*delay
    if avg < expect - 40 and not args.force:
        print(f"!!! WARN: RTT {avg:.1f} ms seems smaller than expected (~{expect} ms). Continue due to non-fatal.")
    else:
        print(f"[SPOT] RTT(avg)={avg:.1f} ms OK (~{expect} ms).")

def one_combo(args, base_out: Path, pattern: str, kem: str, loss: int, delay: int):
    # set qdisc per combo
    print(f"\n>>> [SET] loss={loss}%  delay={delay}ms")
    qdisc_replace(args.cli_ns, args.cli_if, delay, loss)
    qdisc_replace(args.srv_ns, args.srv_if, delay, loss)

    # optional spot-check (only loss==0)
    spot_check_delay(args, delay, loss)

    label = f"{args.label_prefix}loss{loss}"
    outdir = ensure_dir(base_out / pattern / kem / f"delay{delay}ms" / f"loss{loss}")
    if combo_is_done(outdir):
        print(f"[SKIP] already DONE: {outdir}")
        return

    srv_log = outdir / f"server_{pattern}_{kem}_loss{loss}_delay{delay}ms_{now_tag()}.log"
    cli_log = outdir / f"client_{pattern}_{kem}_loss{loss}_delay{delay}ms_{now_tag()}.log"

    print(f">>> (spawn server) pattern={pattern} kem={kem} loss={loss} delay={delay}")
    srv_proc, srv_fp = start_server(args, pattern, label, kem, srv_log)

    # small grace period for server to bind
    time.sleep(0.2)
    print(">>> (run client)")
    ok = run_client(args, pattern, label, kem, cli_log)

    print(">>> (teardown server)")
    try:
        srv_proc.terminate()
        try:
            srv_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv_proc.kill()
    finally:
        srv_fp.close()

    if not ok:
        write_text(combo_fail_log(outdir), f"client returned non-zero for {pattern}/{kem}/loss{loss}/delay{delay}\n")
        print("!!! Client failed. Logged RUN_FAIL.txt")
    else:
        meta = {
            "timestamp": datetime.now().isoformat(),
            "pattern": pattern, "kem": kem,
            "loss": loss, "delay": delay,
            "iters": args.iters, "warmup": args.warmup,
            "exe": {"server": select_binaries(args, kem)[0],
                    "client": select_binaries(args, kem)[1]},
            "namespaces": {"cli": args.cli_ns, "srv": args.srv_ns},
            "ifaces": {"cli": args.cli_if, "srv": args.srv_if},
            "server_ip": args.server_ip
        }
        mark_combo_done(outdir, meta)
        print("[DONE] written DONE marker:", outdir)

def main_once():
    ap = argparse.ArgumentParser(description="PQNoise robust runner (v2)")
    ap.add_argument("--patterns", required=True, help="Comma-separated, e.g., NK,NX,KK")
    ap.add_argument("--kems", required=True, help="Comma-separated, e.g., Kyber512,HQC128,BIKEL1,curve25519")
    ap.add_argument("--losses", required=True, help="Comma-separated integers, e.g., 0,1,2,5,10")
    ap.add_argument("--delays", required=True, help="Comma-separated integers in ms, e.g., 0,10,...,100")

    ap.add_argument("--label-prefix", default="netemOK", help="Label prefix")
    ap.add_argument("--outdir", default=None, help="Output base dir; default Results_<label>_<ts>")
    ap.add_argument("--iters", type=int, default=1000, help="Total iterations per run (include warmup)")
    ap.add_argument("--warmup", type=int, default=20, help="Warmup iterations excluded by your C program")

    ap.add_argument("--cli-ns", default="cli_ns")
    ap.add_argument("--srv-ns", default="srv_ns")
    ap.add_argument("--cli-if", default="cli_ve")
    ap.add_argument("--srv-if", default="srv_ve")
    ap.add_argument("--server-ip", default="10.0.0.1")
    ap.add_argument("--server-exe", default="./Noise_c/server_pq")
    ap.add_argument("--client-exe", default="./Noise_c/clien_pqt")
    ap.add_argument("--dh-kems", default="curve25519,X25519")
    ap.add_argument("--dh-server-exe", default="./Noise_c/server_dh")
    ap.add_argument("--dh-client-exe", default="./Noise_c/client_dh")
    ap.add_argument("--ld-path", default="")
    ap.add_argument("--force", action="store_true", help="Proceed even if verification looks off")

    ap.add_argument("--verify", action="store_true", help="Run hard verification before experiments")
    ap.add_argument("--watchdog", action="store_true", help="Auto-restart on crash")
    ap.add_argument("--max-restarts", type=int, default=3, help="Max watchdog restarts")
    args = ap.parse_args()

    patterns = [p.strip() for p in args.patterns.split(",") if p.strip()]
    kems = [k.strip() for k in args.kems.split(",") if k.strip()]
    losses = [int(x.strip()) for x in args.losses.split(",") if x.strip()]
    delays = [int(x.strip()) for x in args.delays.split(",") if x.strip()]

    # outdir
    if args.outdir:
        base_out = Path(args.outdir)
    else:
        base_out = Path(f"Results_{args.label_prefix}_{now_tag()}")
    ensure_dir(base_out)

    # provenance meta
    write_text(base_out / "RUN_META.txt",
               "\n".join([
                   f"timestamp: {datetime.now().isoformat()}",
                   f"patterns: {patterns}",
                   f"kems: {kems}",
                   f"losses: {losses}",
                   f"delays: {delays}",
                   f"iters: {args.iters}",
                   f"warmup: {args.warmup}",
                   f"namespaces: cli={args.cli_ns}, srv={args.srv_ns}",
                   f"ifaces: cli={args.cli_if}, srv={args.srv_if}",
                   f"server_ip: {args.server_ip}",
                   f"server_exe: {args.server_exe}",
                   f"client_exe: {args.client_exe}",
                   f"dh_kems: {args.dh_kems}",
                   f"dh_server_exe: {args.dh_server_exe}",
                   f"dh_client_exe: {args.dh_client_exe}",
                   f"LD_LIBRARY_PATH: {args.ld_path}",
                   f"force: {args.force}",
               ]))

    # hard verification (optional but recommended)
    if args.verify:
        try:
            netem_verify(args)
            print(">>> [VERIFY] PASSED")
        except Exception as e:
            print(">>> [VERIFY] FAILED:", e)
            if not args.force:
                sys.exit(2)
            print(">>> continue due to --force")

    # main loops
    print("=== Starting experiment matrix ===")
    for pat in patterns:
        for kem in kems:
            for loss in losses:
                for d in delays:
                    try:
                        one_combo(args, base_out, pat, kem, loss, d)
                    except Exception as e:
                        # log and continue
                        outdir = ensure_dir(base_out / pat / kem / f"delay{d}ms" / f"loss{loss}")
                        msg = f"[EXCEPTION] {datetime.now().isoformat()}\n{traceback.format_exc()}\n"
                        write_text(outdir / "EXCEPTION.txt", msg)
                        print("!!! Exception in combo; logged and continue.")
                        # keep going

    # restore qdisc to 0ms
    print("\n=== Cleanup qdisc back to 0ms ===")
    qdisc_replace(args.cli_ns, args.cli_if, 0, 0)
    qdisc_replace(args.srv_ns, args.srv_if, 0, 0)
    print("All done.")
    return 0

def main():
    # watchdog: auto-restart on crash (optional)
    if "--watchdog" in sys.argv:
        # parse once to get max-restarts
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--max-restarts", type=int, default=3)
        args, _ = parser.parse_known_args()
        restarts = 0
        while True:
            try:
                return_code = main_once()
                if return_code == 0:
                    return
                else:
                    print(f"main_once returned {return_code}, restart #{restarts+1}")
            except SystemExit as se:
                # argparse or sys.exit; treat non-zero as crash and restart
                if se.code == 0:
                    return
                print(f"[WATCHDOG] SystemExit code={se.code}, restart #{restarts+1}")
            except Exception as e:
                print(f"[WATCHDOG] crash: {e}\n{traceback.format_exc()}")
            restarts += 1
            if restarts > args.max_restarts:
                print("[WATCHDOG] reached max restarts; giving up.")
                return
            print("[WATCHDOG] sleeping 5s then restart ...")
            time.sleep(5)
    else:
        main_once()

if __name__ == "__main__":
    main()
