"""
Command-Line Interface for LastWord Lock.
"""

import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional

# Configure UTF-8 encoding for Windows terminals
if sys.platform == "win32":
    try:
        if sys.stdout.encoding.lower() != "utf-8":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr.encoding.lower() != "utf-8":
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .container import pack_container, unpack_container, read_container_metadata
from .miner import mine_local
from .coordinator import PoolCoordinator, create_pool_app
from .worker import run_worker_cli
from .benchmark import display_benchmark_table, run_benchmark, parse_time_to_difficulty
from .utils import (
    get_local_ips,
    render_qr_ascii,
    format_bytes,
    format_hashrate,
    format_seconds,
)

console = Console()

BANNER = """[bold cyan]
 _        _    ____ _____ _      _____  ____  ____  _  __
| |      / \\  / ___|_   _| |    |  _  \\|  _ \\|  _ \\| |/ /
| |     / _ \\ \\___ \\ | |  | |    | | | || |_) | | | | ' / 
| |___ / ___ \\ ___) || |  | |___ | |_| ||  _ <| |_| | . \\ 
|_____/_/   \\_|____/ |_|  |_____|____/ |_| \\_\\____/|_|\\_\\
[/bold cyan]
[dim]     Proof-of-Work File Encryption & Distributed Decryption Engine[/dim]
"""

PRESETS_SHA256 = {
    "test": 20,       # ~1M nonces (~1s)
    "demo": 24,       # ~16.7M nonces (~2-4s)
    "quick": 27,      # ~134M nonces (~30-60s)
    "normal": 29,     # ~536M nonces (~2-4 min)
    "hard": 32,       # ~4.3B nonces (~20-40 min)
    "extreme": 35,    # ~34B nonces (~2-4 hours)
    "paranoid": 38,   # ~275B nonces (~1-2 days)
}

PRESETS_SCRYPT = {
    "test": 8,        # 256 nonces (< 1s)
    "demo": 12,       # 4,096 nonces (~2-4s)
    "quick": 14,      # 16,384 nonces (~15-30s)
    "normal": 16,     # 65,536 nonces (~1-2 min)
    "hard": 19,       # 524,288 nonces (~10-20 min)
    "extreme": 22,    # 4,194,304 nonces (~1.5-3 hours)
    "paranoid": 25,   # 33,554,432 nonces (~12-24 hours)
}


@click.group()
def cli():
    """LastWord Lock: File encryption requiring Proof-of-Work mining to decrypt."""
    pass


@cli.command("encrypt")
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-d",
    "--difficulty",
    type=int,
    default=None,
    help="Mining difficulty in bits. Default: 29 for sha256, 16 for scrypt.",
)
@click.option(
    "-p",
    "--preset",
    type=click.Choice(list(PRESETS_SHA256.keys()), case_sensitive=False),
    default=None,
    help="Preset difficulty: test, demo, quick, normal, hard, extreme, paranoid.",
)
@click.option(
    "-t",
    "--target-time",
    type=str,
    default=None,
    help="Calibrate difficulty to target mining duration (e.g. '30s', '5m', '30m', '2h').",
)
@click.option(
    "--algo",
    type=click.Choice(["sha256", "scrypt"], case_sensitive=False),
    default="sha256",
    help="PoW algorithm: sha256 (universal) or scrypt (memory-hard, GPU/ASIC resistant).",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Destination container path (.lwl). Default: <filename>.lwl",
)
@click.option(
    "--delete-original",
    is_flag=True,
    help="Delete the original plaintext file after successful encryption.",
)
def cmd_encrypt(
    file_path: Path,
    difficulty: Optional[int],
    preset: Optional[str],
    target_time: Optional[str],
    algo: str,
    output: Optional[Path],
    delete_original: bool,
):
    """Encrypt a file with instant O(1) PoW puzzle."""
    console.print(BANNER)
    algo = algo.lower()

    # Large file warning
    file_size = file_path.stat().st_size
    if file_size > 500 * 1024 * 1024:
        console.print("[yellow]Notice: Large file (>500MB). Ensure sufficient RAM for encryption.[/yellow]")

    # Measure actual device speed dynamically for the chosen algorithm
    with console.status(f"[cyan]Calibrating hardware throughput for {algo.upper()}..."):
        single_rate, multi_rate, cpu_count = run_benchmark(sample_seconds=0.2, algo=algo)

    # Determine difficulty
    presets_table = PRESETS_SCRYPT if algo == "scrypt" else PRESETS_SHA256
    if target_time:
        diff = parse_time_to_difficulty(target_time, multi_rate)
        console.print(
            f"[green]✓[/green] Calibrated to [bold yellow]{diff} bits[/bold yellow] "
            f"for target '{target_time}' ({algo.upper()}) based on local hashrate ({format_hashrate(multi_rate)})."
        )
    elif preset:
        diff = presets_table[preset.lower()]
        console.print(f"[green]✓[/green] Selected preset [bold cyan]'{preset}'[/bold cyan]: [bold yellow]{diff} bits[/bold yellow].")
    elif difficulty is not None:
        diff = difficulty
    else:
        diff = 16 if algo == "scrypt" else 29

    out_path = output or file_path.with_name(f"{file_path.name}.lwl")

    with console.status("[bold cyan]Generating puzzle and authenticating container..."):
        meta = pack_container(file_path, out_path, difficulty=diff, pow_alg=algo)

    avg_hashes = meta.search_space // 2
    est_single = format_seconds(avg_hashes / max(0.001, single_rate))
    est_multi = format_seconds(avg_hashes / max(0.001, multi_rate))

    info_table = Table(box=None, show_header=False, pad_edge=False)
    info_table.add_row("[bold]Source File:[/bold]", f"[cyan]{file_path.name}[/cyan]")
    info_table.add_row("[bold]Original Size:[/bold]", format_bytes(meta.file_size))
    info_table.add_row("[bold]Target Container:[/bold]", f"[green]{out_path}[/green]")
    info_table.add_row("[bold]PoW Algorithm:[/bold]", f"[bold cyan]{meta.pow_alg.upper()}[/bold cyan]")
    info_table.add_row("[bold]Difficulty:[/bold]", f"[bold yellow]{diff} bits[/bold yellow]")
    info_table.add_row("[bold]Total Search Space:[/bold]", f"{meta.search_space:,} nonces")
    info_table.add_row("[bold]Expected Hashes:[/bold]", f"~{avg_hashes:,} hashes")
    info_table.add_row(f"[bold]Est. 1 Core ({format_hashrate(single_rate)}):[/bold]", f"[dim]{est_single}[/dim]")
    info_table.add_row(f"[bold]Est. All Cores ({format_hashrate(multi_rate)}):[/bold]", f"[bold magenta]{est_multi}[/bold magenta]")

    if algo == "sha256":
        est_gpu = format_seconds(avg_hashes / 20_000_000_000)  # Modern RTX 4090 ~ 20 GH/s
        info_table.add_row("[bold]Est. RTX 4090 (~20 GH/s):[/bold]", f"[yellow]{est_gpu}[/yellow]")
    else:
        est_gpu = format_seconds(avg_hashes / 25_000)  # Scrypt memory-bound GPU ~ 25 KH/s
        info_table.add_row("[bold]Est. High-End GPU (~25 KH/s):[/bold]", f"[yellow]{est_gpu}[/yellow]")

    console.print(
        Panel(
            info_table,
            title="[bold green]✓ File Successfully Encrypted (Header Authenticated)[/bold green]",
            border_style="green",
        )
    )

    if algo == "sha256":
        console.print(
            "[dim]💡 Note: GPUs achieve ~20 GH/s on SHA-256 (~10,000x over CPUs). "
            "For reduced GPU advantage, consider '--algo scrypt' (gap ~100x).[/dim]"
        )

    if delete_original:
        file_path.unlink()
        console.print("[yellow]Original plaintext file removed.[/yellow]")


@cli.command("decrypt")
@click.argument("container_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Destination for decrypted file. Default: original filename.",
)
@click.option(
    "-t",
    "--threads",
    type=int,
    default=None,
    help="Number of CPU worker threads. Default: all available cores.",
)
def cmd_decrypt(container_path: Path, output: Optional[Path], threads: Optional[int]):
    """Mine and decrypt a container locally on this machine."""
    console.print(BANNER)

    meta, _, _ = read_container_metadata(container_path)
    safe_name = Path(meta.original_filename).name or "unlocked_file"
    out_file = output or container_path.parent / safe_name

    cores = threads or os.cpu_count() or 4
    console.print(
        Panel.fit(
            f"[bold cyan]Local Decryption Miner[/bold cyan]\n"
            f"Target: [bold]{safe_name}[/bold] ({format_bytes(meta.file_size)})\n"
            f"Algorithm: [bold cyan]{meta.pow_alg.upper()}[/bold cyan]\n"
            f"Difficulty: [yellow]{meta.difficulty} bits[/yellow] ({meta.search_space:,} nonces)\n"
            f"CPU Workers: [magenta]{cores} cores[/magenta]",
            border_style="cyan",
        )
    )

    winning_nonce, elapsed, hashes_done = mine_local(
        salt=meta.salt,
        target_hash=meta.target_hash,
        search_space=meta.search_space,
        threads=cores,
        algo=meta.pow_alg,
        console=console,
    )

    if winning_nonce is None:
        console.print("[bold red]Failed to find winning nonce.[/bold red]")
        sys.exit(1)

    with console.status("[bold green]Verifying solution and authenticating container..."):
        unpacked_path = unpack_container(container_path, out_file, winning_nonce)

    rate = hashes_done / elapsed if elapsed > 0 else 0
    console.print(
        Panel.fit(
            f"[bold green]🎉 FILE UNLOCKED & RESTORED![/bold green]\n\n"
            f"Output File: [bold cyan]{unpacked_path}[/bold cyan]\n"
            f"Winning Nonce: [bold yellow]{winning_nonce}[/bold yellow]\n"
            f"Elapsed Time: [magenta]{elapsed:.2f}s[/magenta]\n"
            f"Average Hashrate: [cyan]{format_hashrate(rate)}[/cyan]",
            border_style="green",
        )
    )


@cli.command("pool")
@click.argument("container_path", type=click.Path(exists=True, path_type=Path))
@click.option("--host", type=str, default="0.0.0.0", help="Host address to bind pool server.")
@click.option("--port", type=int, default=8080, help="Port to listen on. Default: 8080.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Output destination for unlocked file.")
@click.option("--contest", is_flag=True, help="Enable contest mode: only the winning solver can claim/download the file.")
@click.option("--mine/--no-mine", "mine", default=None, help="Also mine locally on coordinator. Default: off in contest, on otherwise.")
@click.option("-t", "--threads", type=int, default=None, help="CPU threads for coordinator miner.")
def cmd_pool(
    container_path: Path,
    host: str,
    port: int,
    output: Optional[Path],
    contest: bool,
    mine: Optional[bool],
    threads: Optional[int],
):
    """Start a mining pool coordinator with Web Miner & REST/WebSocket API."""
    import uvicorn

    console.print(BANNER)
    coordinator = PoolCoordinator(container_path, output_path=output, contest_mode=contest)
    app = create_pool_app(coordinator)

    local_ips = get_local_ips()
    primary_ip = local_ips[0] if local_ips else "127.0.0.1"
    web_url = f"http://{primary_ip}:{port}"

    console.print(
        Panel.fit(
            f"[bold cyan]LASTWORD-LOCK MINING POOL COORDINATOR[/bold cyan]\n"
            f"Container: [bold]{coordinator.metadata.original_filename}[/bold] "
            f"({coordinator.metadata.difficulty} bits, {coordinator.metadata.search_space:,} nonces)\n"
            f"Algorithm: [bold cyan]{coordinator.metadata.pow_alg.upper()}[/bold cyan]\n"
            f"Mode: {'[bold yellow]CONTEST (Winner-Only Claim)[/bold yellow]' if contest else '[green]Collaborative Decryption[/green]'}\n"
            f"Local Web URL: [bold yellow]http://localhost:{port}[/bold yellow]\n"
            f"Network URL:   [bold green]{web_url}[/bold green]\n\n"
            f"[dim]Any phone, laptop, or server on your WiFi can join and mine at:[/dim]\n"
            f"[bold underline cyan]{web_url}[/bold underline cyan]",
            border_style="cyan",
        )
    )

    qr_text = render_qr_ascii(web_url)
    if qr_text:
        console.print("[dim]Scan QR code with smartphone camera to start mining instantly:[/dim]")
        console.print(qr_text)

    # Organizer host miner: default disabled in contest mode, enabled in collaborative mode
    should_mine = (not contest) if mine is None else mine

    if should_mine:
        def background_miner():
            time.sleep(1.5)
            client_cores = threads or max(1, (os.cpu_count() or 4) - 1)
            run_worker_cli(
                f"http://127.0.0.1:{port}",
                worker_name="Coordinator Host",
                threads=client_cores,
                console=Console(quiet=True),
            )

        t = threading.Thread(target=background_miner, daemon=True)
        t.start()
    else:
        if contest:
            console.print("[dim]Host local mining is disabled by default in contest mode.[/dim]")

    uvicorn.run(app, host=host, port=port, log_level="warning")


@cli.command("worker")
@click.argument("pool_url", type=str)
@click.option("-n", "--name", type=str, default=None, help="Worker display name.")
@click.option("-t", "--threads", type=int, default=None, help="CPU worker threads.")
def cmd_worker(pool_url: str, name: Optional[str], threads: Optional[int]):
    """Join a mining pool as a high-performance CLI worker."""
    console.print(BANNER)
    run_worker_cli(pool_url, worker_name=name, threads=threads, console=console)


@cli.command("inspect")
@click.argument("container_path", type=click.Path(exists=True, path_type=Path))
def cmd_inspect(container_path: Path):
    """Inspect metadata and difficulty requirements of an .lwl container."""
    console.print(BANNER)
    meta, _, _ = read_container_metadata(container_path)

    table = Table(title=f"Container: {container_path.name}", border_style="cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Original Filename", meta.original_filename)
    table.add_row("Original Size", format_bytes(meta.file_size))
    table.add_row("SHA-256 Checksum", meta.file_sha256)
    table.add_row("PoW Algorithm", meta.pow_alg.upper())
    table.add_row("PoW Difficulty", f"{meta.difficulty} bits")
    table.add_row("Search Space", f"{meta.search_space:,} nonces")
    table.add_row("Average Expected Hashes", f"{meta.search_space // 2:,} hashes")
    table.add_row("Salt (hex)", meta.salt.hex())
    table.add_row("Target Hash (hex)", meta.target_hash.hex())
    table.add_row("Encrypted Key Blob", meta.encrypted_key.hex()[:32] + "...")
    table.add_row("Creation Timestamp", meta.created_at)

    console.print(table)


@cli.command("benchmark")
@click.option(
    "--algo",
    type=click.Choice(["sha256", "scrypt"], case_sensitive=False),
    default="sha256",
    help="PoW algorithm to benchmark (sha256 or scrypt).",
)
def cmd_benchmark(algo: str):
    """Benchmark local CPU hashrates and display difficulty calibration table."""
    console.print(BANNER)
    display_benchmark_table(console, algo=algo.lower())


def main():
    cli()


if __name__ == "__main__":
    main()
