#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""机场监控定时器 —— 持续运行，自动定时采集所有机场。

用法:
  以管理员身份打开 PowerShell 或终端:
  python monitor.py                # 默认每3小时
  python monitor.py --interval 1  # 每1小时
  python monitor.py --interval 0.5  # 每30分钟
  python monitor.py --once        # 只跑一次然后退出
  python monitor.py --airport maxiong,bywave  # 只监控指定机场
"""
import subprocess, sys, os, time, argparse, signal
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

def run_once(airports=None, verbose=True):
    """跑一次全量采集。"""
    cmd = [sys.executable, os.path.join(HERE, "run.py"), "all"]
    if verbose:
        cmd.append("-v")
    if airports:
        cmd += ["--airport", airports]
    
    print(f"\n{'='*60}")
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] 开始采集...")
    print(f"{'='*60}")
    
    t0 = time.time()
    r = subprocess.run(cmd, cwd=HERE)
    elapsed = time.time() - t0
    
    print(f"\n[完成] 耗时 {elapsed:.0f}秒 ({elapsed/60:.1f}分钟)")
    print(f"{'='*60}\n")
    return r.returncode == 0


def main():
    p = argparse.ArgumentParser(description="机场监控定时器")
    p.add_argument("--interval", type=float, default=3, 
                   help="间隔小时数（默认3，0.5=30分钟）")
    p.add_argument("--once", action="store_true", help="只跑一次后退出")
    p.add_argument("--airport", default=None, help="只监控指定机场（逗号分隔）")
    p.add_argument("-q", "--quiet", action="store_true", help="不显示verbose")
    args = p.parse_args()

    print(f"机场监控定时器")
    print(f"项目: {HERE}")
    print(f"间隔: 每{args.interval}小时")
    if args.airport:
        print(f"机场: {args.airport}")
    print(f"按 Ctrl+C 停止")
    print()

    # Ctrl+C 优雅退出
    def signal_handler(sig, frame):
        print(f"\n[{datetime.now():%H:%M:%S}] 收到停止信号，退出")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        try:
            run_once(args.airport, not args.quiet)
        except Exception as e:
            print(f"[错误] {e}")

        if args.once:
            print("单次模式，退出")
            break

        # 等待下次
        wait = int(args.interval * 3600)
        next_time = datetime.now().timestamp() + wait
        next_str = datetime.fromtimestamp(next_time).strftime("%H:%M:%S")
        print(f"下次运行: {next_str}（{args.interval}小时后）")
        print(f"按 Ctrl+C 停止\n")
        
        # 分段sleep以便Ctrl-C能快速响应
        for _ in range(wait):
            time.sleep(1)


if __name__ == "__main__":
    main()
