"""
Benchmarking and difficulty calibration engine.
Measures device hashrates and predicts mining times across difficulty tiers
for both universal SHA-256 and memory-hard Scrypt algorithms.
"""

import os
import time
import struct
import hashlib
import re
from typing import Tuple, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .miner import mine_local
from .utils import format_hashrate, format_seconds


def run_benchmark(
    sample_seconds: float = 0.8,
    threads: Optional[int] = None,
    algo: str = "sha256",
) -> Tuple[float, float, int]:
    """
    Run single-core and multi-core benchmark for the specified PoW algorithm.
    Returns (single_core_rate, multi_core_rate, cpu_count).
    """
    cpu_count = threads or os.cpu_count() or 4
    salt = b"benchmark_salt_1"
    target = hashlib.sha256(b"dummy").digest()

    if algo == "scrypt":
        # Scrypt memory-hard test (N=16384, r=8, p=1 ~16MB RAM)
        scrypt = hashlib.scrypt
        buf = bytearray(salt + b"\x00" * 8)
        pack_into = struct.pack_into
        
        # 1. Single core test: 30 iterations
        n_single = 30
        t0 = time.perf_counter()
        for i in range(n_single):
            pack_into(">Q", buf, 16, i)
            scrypt(buf, salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024)
        t1 = time.perf_counter()
        single_rate = n_single / max(0.001, t1 - t0)

        # 2. Multi-core test
        n_multi = max(40, int(single_rate * sample_seconds * cpu_count * 0.7))
        _, multi_dt, multi_done = mine_local(
            salt=salt,
            target_hash=b"\xff" * 32,
            search_space=n_multi,
            threads=cpu_count,
            algo="scrypt",
            console=Console(quiet=True),
        )
        multi_rate = multi_done / max(0.001, multi_dt)
        return single_rate, multi_rate, cpu_count

    else:
        # 1. Single core SHA-256 test
        t0 = time.perf_counter()
        n_sample = 800_000
        buf = bytearray(salt + b"\x00" * 8)
        pack_into = struct.pack_into
        sha256 = hashlib.sha256

        for i in range(n_sample):
            pack_into(">Q", buf, 16, i)
            if sha256(buf).digest() == target:
                break
        t1 = time.perf_counter()
        single_rate = n_sample / max(0.0001, t1 - t0)

        # 2. Multi-core SHA-256 test
        multi_sample = int(single_rate * sample_seconds * cpu_count * 0.6)
        _, multi_dt, multi_done = mine_local(
            salt=salt,
            target_hash=b"\xff" * 32,
            search_space=multi_sample,
            threads=cpu_count,
            algo="sha256",
            console=Console(quiet=True),
        )
        multi_rate = multi_done / max(0.001, multi_dt)
        return single_rate, multi_rate, cpu_count


def parse_time_to_difficulty(time_str: str, hashrate: float) -> int:
    """
    Parse strings like '30s', '5m', '2h', '1d' and compute difficulty D
    such that 2^(D - 1) / hashrate ≈ target seconds.
    """
    units = {
        "s": 1,
        "sec": 1,
        "m": 60,
        "min": 60,
        "h": 3600,
        "hr": 3600,
        "d": 86400,
        "day": 86400,
    }
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?$", time_str.strip())
    if not match:
        raise ValueError(f"Invalid time format: '{time_str}'. Example: '30s', '5m', '1h'")

    val = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    if unit not in units:
        raise ValueError(f"Unknown time unit '{unit}'. Use s, m, h, or d.")

    target_seconds = val * units[unit]
    expected_hashes = max(10.0, target_seconds * max(1.0, hashrate))
    import math

    diff = int(round(math.log2(expected_hashes) + 1))
    return max(4, min(56, diff))


def display_benchmark_table(console: Optional[Console] = None, algo: str = "sha256"):
    """
    Run benchmark and display a rich comparative table tailored to the selected algorithm.
    """
    console = console or Console()
    algo = algo.lower()

    with console.status(f"[bold cyan]Benchmarking CPU for {algo.upper()}..."):
        single_rate, multi_rate, cpu_count = run_benchmark(sample_seconds=0.6, algo=algo)

    table = Table(
        title=f"Hardware Hashrate & Difficulty Calibration ({algo.upper()})",
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Difficulty", justify="center", style="yellow")
    table.add_column("Preset", justify="center", style="bold cyan")
    table.add_column("Search Space", justify="right", style="cyan")
    table.add_column("Avg Hashes", justify="right", style="dim")
    table.add_column("1 CPU Core", justify="right", style="magenta")
    table.add_column(f"All Cores ({cpu_count}c)", justify="right", style="bold green")

    if algo == "scrypt":
        table.add_column("GPU (est. ~25 KH/s)*", justify="right", style="yellow")
        diff_levels = [
            (8, "test"),
            (12, "demo"),
            (14, "quick"),
            (16, "normal [default]"),
            (18, "medium"),
            (20, "hard"),
            (22, "extreme"),
            (25, "paranoid"),
            (28, "fortress"),
        ]
        gpu_rate = 25_000.0
    else:
        table.add_column("RTX 4090 (~20 GH/s)", justify="right", style="yellow")
        diff_levels = [
            (20, "test"),
            (24, "demo"),
            (27, "quick"),
            (29, "normal [default]"),
            (31, "-"),
            (32, "hard"),
            (35, "extreme"),
            (38, "paranoid"),
            (40, "fortress"),
            (48, "gpu-target"),
        ]
        gpu_rate = 20_000_000_000.0

    for d, preset_label in diff_levels:
        space = 1 << d
        avg_hashes = space // 2
        time_1c = format_seconds(avg_hashes / max(0.001, single_rate))
        time_all = format_seconds(avg_hashes / max(0.001, multi_rate))
        time_gpu = format_seconds(avg_hashes / gpu_rate)

        table.add_row(
            f"{d} bits",
            preset_label,
            f"{space:,}",
            f"{avg_hashes:,}",
            time_1c,
            time_all,
            time_gpu,
        )

    console.print(
        Panel.fit(
            f"[bold]Detected Hardware:[/bold] {cpu_count} CPU Cores\n"
            f"[bold]Algorithm:[/bold] [bold cyan]{algo.upper()}[/bold cyan]\n"
            f"[bold]Single-Core Hashrate:[/bold] [cyan]{format_hashrate(single_rate)}[/cyan]\n"
            f"[bold]Multi-Core Hashrate:[/bold] [green]{format_hashrate(multi_rate)}[/green]",
            border_style="cyan",
        )
    )
    console.print(table)
    if algo == "scrypt":
        console.print(
            "[dim]* Note: 25 KH/s GPU speed is an estimate based on VRAM bandwidth (~16MB memory-hard attempts).\n"
            "  Scrypt compresses the GPU:CPU gap from ~10,000x to ~100x (~25 KH/s vs ~200 H/s on CPU),\n"
            "  but GPU owners still hold an advantage in parallel search. Absolute device equality requires sequential RSW puzzles.[/dim]\n"
        )
    else:
        console.print(
            "[dim]* Note: Parallel SHA-256 has a ~10,000x gap between RTX 4090 (~20 GH/s) and typical multi-core CPU (~2 MH/s).\n"
            "  A 48-bit puzzle takes only ~2 hours on a single RTX 4090. Use '--algo scrypt' to narrow the hardware gap.[/dim]\n"
        )
