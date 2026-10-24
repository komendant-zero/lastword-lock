"""
Benchmarking engine for LastWord Lock.
Measures device cryptographic throughput for universal SHA-256 and memory-hard Scrypt algorithms.
"""

import os
import time
import struct
import hashlib
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


def display_benchmark_table(console: Optional[Console] = None, algo: str = "sha256"):
    """
    Run benchmark and display device cryptographic throughput.
    """
    console = console or Console()
    algo = algo.lower()

    with console.status(f"[bold cyan]Benchmarking CPU for {algo.upper()}..."):
        single_rate, multi_rate, cpu_count = run_benchmark(sample_seconds=0.6, algo=algo)

    table = Table(
        title=f"Hardware Hashrate Benchmark ({algo.upper()})",
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Algorithm", algo.upper())
    table.add_row("CPU Cores Detected", str(cpu_count))
    table.add_row("Single-Core Throughput", format_hashrate(single_rate))
    table.add_row(f"All Cores Combined ({cpu_count}c)", format_hashrate(multi_rate))

    console.print(table)
