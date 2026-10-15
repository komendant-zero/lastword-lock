"""
High-performance multiprocessing miner engine for local CPU mining.
Optimized for multi-core Windows, Linux, and macOS execution.
Supports both fast SHA-256 and memory-hard Scrypt algorithms.
"""

import os
import time
import struct
import hashlib
import multiprocessing as mp
from typing import Optional, Tuple
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.live import Live

from .utils import format_hashrate, format_seconds


def _worker_loop(
    salt: bytes,
    target_hash: bytes,
    start_nonce: int,
    end_nonce: int,
    batch_size: int,
    stop_event: mp.Event,
    progress_counter: mp.Value,
    solution_value: mp.Value,
    algo: str = "sha256",
):
    """
    Worker process mining loop.
    Supports sha256 and memory-hard scrypt.
    """
    buf = bytearray(salt + b"\x00" * 8)
    pack_into = struct.pack_into
    sha256 = hashlib.sha256
    scrypt = hashlib.scrypt

    curr = start_nonce
    while curr < end_nonce:
        if stop_event.is_set():
            return

        batch_end = min(curr + batch_size, end_nonce)
        batch_count = batch_end - curr

        if algo == "scrypt":
            for n in range(curr, batch_end):
                pack_into(">Q", buf, 16, n)
                h = scrypt(buf, salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024)[:32]
                if h == target_hash:
                    with solution_value.get_lock():
                        solution_value.value = n
                    stop_event.set()
                    return
        else:
            for n in range(curr, batch_end):
                pack_into(">Q", buf, 16, n)
                if sha256(buf).digest() == target_hash:
                    with solution_value.get_lock():
                        solution_value.value = n
                    stop_event.set()
                    return

        with progress_counter.get_lock():
            progress_counter.value += batch_count

        curr = batch_end


def mine_local(
    salt: bytes,
    target_hash: bytes,
    search_space: int,
    threads: Optional[int] = None,
    batch_size: Optional[int] = None,
    algo: str = "sha256",
    console: Optional[Console] = None,
) -> Tuple[Optional[int], float, int]:
    """
    Mine local search space [0, search_space) using multiprocessing.
    Returns (winning_nonce, elapsed_seconds, total_hashes_done).
    """
    if threads is None or threads <= 0:
        threads = os.cpu_count() or 4

    if batch_size is None:
        batch_size = 50 if algo == "scrypt" else 50_000

    console = console or Console()

    stop_event = mp.Event()
    progress_counter = mp.Value("q", 0)
    solution_value = mp.Value("q", -1)

    # Partition search space evenly across workers
    chunk_size = (search_space + threads - 1) // threads
    processes = []

    for i in range(threads):
        worker_start = i * chunk_size
        worker_end = min((i + 1) * chunk_size, search_space)
        if worker_start >= search_space:
            break

        p = mp.Process(
            target=_worker_loop,
            args=(
                salt,
                target_hash,
                worker_start,
                worker_end,
                batch_size,
                stop_event,
                progress_counter,
                solution_value,
                algo,
            ),
        )
        p.daemon = True
        processes.append(p)

    t0 = time.perf_counter()
    for p in processes:
        p.start()

    last_hashes = 0
    last_time = t0
    current_hashrate = 0.0

    task_title = f"Mining ({algo.upper()})..."
    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="bright_black", complete_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
        TextColumn("• [yellow]{task.completed:,.0f}/{task.total:,.0f} nonces"),
        TextColumn("• [bold magenta]{task.fields[hashrate]}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            task_title,
            total=search_space,
            completed=0,
            hashrate="0.0 H/s",
        )

        try:
            while not stop_event.is_set():
                time.sleep(0.15)
                now = time.perf_counter()
                with progress_counter.get_lock():
                    done = progress_counter.value

                dt = now - last_time
                if dt >= 0.5:
                    d_hashes = done - last_hashes
                    current_hashrate = d_hashes / dt if dt > 0 else 0.0
                    last_hashes = done
                    last_time = now

                progress.update(
                    task_id,
                    completed=min(done, search_space),
                    hashrate=format_hashrate(current_hashrate),
                )

                if not any(p.is_alive() for p in processes):
                    break

        except KeyboardInterrupt:
            stop_event.set()
            console.print("\n[yellow]Mining interrupted by user.[/yellow]")

        finally:
            stop_event.set()
            for p in processes:
                p.join(timeout=0.2)
                if p.is_alive():
                    p.terminate()

    t1 = time.perf_counter()
    elapsed = max(0.001, t1 - t0)
    with progress_counter.get_lock():
        total_hashes = progress_counter.value

    winning_nonce = None
    with solution_value.get_lock():
        if solution_value.value >= 0:
            winning_nonce = solution_value.value

    return winning_nonce, elapsed, total_hashes
