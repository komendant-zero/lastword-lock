"""
CLI Worker client for LastWord Lock Mining Pools.
Connects to a coordinator pool over the local network or internet,
fetches nonce range leases, mines with maximum CPU performance,
submits candidate solutions, and securely claims/downloads the unlocked file.
"""

import os
import sys
import time
import socket
import hashlib
from pathlib import Path
import urllib.parse
from typing import Optional
import multiprocessing as mp

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

from .miner import _worker_loop
from .utils import format_hashrate, format_seconds


def run_worker_cli(
    pool_url: str,
    worker_name: Optional[str] = None,
    threads: Optional[int] = None,
    console: Optional[Console] = None,
    download_on_win: bool = True,
):
    """
    Connect to a pool and mine assigned ranges until solved.
    If this worker finds the solution, it automatically claims and downloads the decrypted file!
    """
    console = console or Console()
    threads = threads or os.cpu_count() or 4
    hostname = socket.gethostname()
    worker_name = worker_name or f"{hostname} ({threads}c)"
    worker_id = f"cli_{hostname}_{os.getpid()}_{int(time.time())}"

    pool_url = pool_url.rstrip("/")
    if not pool_url.startswith("http://") and not pool_url.startswith("https://"):
        pool_url = "http://" + pool_url

    console.print(
        Panel.fit(
            f"[bold cyan]LASTWORD-LOCK CLI WORKER[/bold cyan]\n"
            f"Pool URL: [bold yellow]{pool_url}[/bold yellow]\n"
            f"Worker Name: [green]{worker_name}[/green]\n"
            f"Threads: [magenta]{threads} CPU cores[/magenta]",
            border_style="cyan",
        )
    )

    client = httpx.Client(timeout=15.0)

    # 1. Fetch info
    try:
        res = client.get(f"{pool_url}/api/info")
        res.raise_for_status()
        info = res.json()
    except Exception as e:
        console.print(f"[bold red]Failed to connect to pool at {pool_url}:[/bold red] {e}")
        return

    algo = info.get("pow_alg", "sha256")
    is_contest = info.get("contest_mode", False)

    console.print(
        f"[green]✓[/green] Connected! Target file: [bold]{info['filename']}[/bold] "
        f"({info['difficulty']} bits, {info['search_space']:,} search space, [cyan]{algo.upper()}[/cyan]"
        f"{' • [bold yellow]CONTEST MODE[/bold yellow]' if is_contest else ''})\n"
    )

    if info.get("is_solved"):
        console.print(f"[bold green]File is already unlocked![/bold green] Solution: {info.get('solution')}")
        return

    salt = bytes.fromhex(info["salt"])
    target_hash = bytes.fromhex(info["target_hash"])

    total_worker_hashes = 0
    t0_start = time.perf_counter()

    try:
        while True:
            job_url = (
                f"{pool_url}/api/job?"
                f"worker_id={urllib.parse.quote(worker_id)}&"
                f"name={urllib.parse.quote(worker_name)}&"
                f"device=cli&cores={threads}"
            )
            try:
                res = client.get(job_url)
                res.raise_for_status()
                job = res.json()
            except Exception as e:
                console.print(f"[yellow]Job fetch error: {e}. Retrying in 2s...[/yellow]")
                time.sleep(2.0)
                continue

            status = job.get("status")
            if status == "solved":
                console.print(
                    Panel.fit(
                        f"[bold green]🎉 FILE UNLOCKED BY POOL![/bold green]\n"
                        f"Winning Nonce: [bold yellow]{job.get('solution')}[/bold yellow]\n"
                        f"Discovered By: [cyan]{job.get('solved_by')}[/cyan]",
                        border_style="green",
                    )
                )
                break

            if status == "waiting" or status != "work":
                time.sleep(1.0)
                continue

            lease_id = job["lease_id"]
            start_nonce = job["start"]
            end_nonce = job["end"]
            chunk_hashes = end_nonce - start_nonce
            pow_alg = job.get("pow_alg", algo)

            stop_event = mp.Event()
            progress_counter = mp.Value("q", 0)
            solution_value = mp.Value("q", -1)

            per_thread = (chunk_hashes + threads - 1) // threads
            procs = []
            batch_sz = 50 if pow_alg == "scrypt" else 25000

            for t in range(threads):
                s = start_nonce + t * per_thread
                e = min(start_nonce + (t + 1) * per_thread, end_nonce)
                if s >= end_nonce:
                    break
                p = mp.Process(
                    target=_worker_loop,
                    args=(
                        salt,
                        target_hash,
                        s,
                        e,
                        batch_sz,
                        stop_event,
                        progress_counter,
                        solution_value,
                        pow_alg,
                    ),
                )
                p.daemon = True
                procs.append(p)

            t0_chunk = time.perf_counter()
            for p in procs:
                p.start()

            for p in procs:
                p.join()

            t1_chunk = time.perf_counter()
            chunk_time = max(0.001, t1_chunk - t0_chunk)
            chunk_rate = chunk_hashes / chunk_time
            total_worker_hashes += chunk_hashes

            found_nonce = None
            with solution_value.get_lock():
                if solution_value.value >= 0:
                    found_nonce = solution_value.value

            if found_nonce is not None:
                console.print(
                    Panel.fit(
                        f"[bold green]🌟 MATCH FOUND BY THIS WORKER![/bold green]\n"
                        f"Winning Nonce: [bold yellow]{found_nonce}[/bold yellow]\n"
                        f"Submitting to coordinator pool...",
                        border_style="green",
                    )
                )
                # Commit-reveal protection against HTTP packet sniffing / front-running
                commit_hash = hashlib.sha256(f"{found_nonce}:{worker_id}".encode()).hexdigest()
                try:
                    client.post(
                        f"{pool_url}/api/commit",
                        json={"worker_id": worker_id, "commit": commit_hash},
                        timeout=5.0,
                    )
                except Exception:
                    pass

                claim_token = None
                for attempt in range(1, 11):
                    try:
                        submit_res = client.post(
                            f"{pool_url}/api/submit",
                            json={"worker_id": worker_id, "name": worker_name, "nonce": found_nonce},
                        )
                        if submit_res.status_code == 200:
                            sub_data = submit_res.json()
                            claim_token = sub_data.get("claim_token")
                            console.print("[bold green]✓ Solution verified and accepted by pool coordinator![/bold green]")
                            break
                        elif submit_res.status_code == 400:
                            console.print(f"[bold red]❌ Pool rejected candidate: {submit_res.text}. Contest may already be solved or nonce invalid.[/bold red]")
                            break
                        else:
                            console.print(f"[yellow]Attempt {attempt}/10: submit returned {submit_res.status_code}. Retrying...[/yellow]")
                    except Exception as ex:
                        console.print(f"[yellow]Attempt {attempt}/10: failed to submit solution ({ex}). Retrying in {min(10, int(1.5 * attempt))}s...[/yellow]")
                    time.sleep(min(10.0, 1.5 * attempt))

                # Automatically claim & download the unlocked prize file if requested
                if download_on_win and claim_token:
                    for dl_attempt in range(1, 5):
                        try:
                            # Use X-Claim-Token header to avoid token exposure in access logs/URLs
                            dl_res = client.get(
                                f"{pool_url}/api/download",
                                headers={"X-Claim-Token": claim_token},
                            )
                            if dl_res.status_code == 200:
                                safe_name = Path(info["filename"]).name or "unlocked_file"
                                out_claimed = Path(f"claimed_{safe_name}")
                                out_claimed.write_bytes(dl_res.content)
                                console.print(
                                    Panel.fit(
                                        f"[bold green]🏆 PRIZE CLAIMED & DOWNLOADED LOCALLY![/bold green]\n"
                                        f"Saved as: [bold cyan]{out_claimed.resolve()}[/bold cyan]\n"
                                        f"File Size: [magenta]{len(dl_res.content):,} bytes[/magenta]",
                                        border_style="green",
                                    )
                                )
                                break
                        except Exception as e:
                            time.sleep(1.5)
                break
            else:
                try:
                    client.post(
                        f"{pool_url}/api/progress",
                        json={
                            "worker_id": worker_id,
                            "lease_id": lease_id,
                            "hashes_done": chunk_hashes,
                            "hashrate": chunk_rate,
                            "name": worker_name,
                        },
                    )
                except Exception:
                    pass

                console.print(
                    f"Range [{start_nonce:,}..{end_nonce:,}] scanned in {chunk_time:.2f}s "
                    f"([bold cyan]{format_hashrate(chunk_rate)}[/bold cyan]) • "
                    f"Total hashes: {total_worker_hashes:,}"
                )

    except KeyboardInterrupt:
        console.print("\n[yellow]Worker stopped by user.[/yellow]")
    finally:
        client.close()
