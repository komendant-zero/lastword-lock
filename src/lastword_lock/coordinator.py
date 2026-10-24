"""
FastAPI Coordinator Server for LastWord Lock Mining Pool.
Coordinates range leases between CLI workers and web browser workers,
verifies solutions, triggers decryption,
and broadcasts live pool telemetry.
"""

import os
import time
import uuid
import secrets
import hashlib
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Header, Request
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel

from .container import read_container_metadata, unpack_container, ContainerMetadata
from .crypto import verify_nonce


class ProgressReport(BaseModel):
    worker_id: str
    lease_id: Optional[str] = None
    hashes_done: int = 0
    hashrate: float = 0.0
    name: Optional[str] = None


class SolutionSubmit(BaseModel):
    worker_id: str
    name: Optional[str] = None
    nonce: int


@dataclass
class Lease:
    lease_id: str
    start: int
    end: int
    worker_id: str
    created_at: float
    expires_at: float


@dataclass
class WorkerRecord:
    worker_id: str
    name: str
    device: str
    cores: int
    hashrate: float = 0.0
    total_hashes: int = 0
    last_seen: float = field(default_factory=time.time)


class PoolCoordinator:
    def __init__(
        self,
        container_path: Path,
        output_path: Optional[Path] = None,
        chunk_size: Optional[int] = None,
    ):
        self.container_path = Path(container_path)
        self.metadata, self.payload_offset, self.header_bytes = read_container_metadata(self.container_path)
        
        # Path traversal protection for default output path
        safe_original_name = Path(self.metadata.original_filename).name or "unlocked_file"
        self.output_path = (
            Path(output_path)
            if output_path
            else self.container_path.parent / f"decrypted_{safe_original_name}"
        )

        is_scrypt = self.metadata.pow_alg == "scrypt"
        if chunk_size is None or chunk_size <= 0:
            if is_scrypt:
                # Scrypt is memory-hard: 50 - 1,000 nonces per chunk
                self.chunk_size = max(20, min(1_000, self.metadata.search_space // 50))
            else:
                # SHA-256: 500,000 to 10,000,000 nonces per chunk
                self.chunk_size = max(500_000, min(10_000_000, self.metadata.search_space // 500))
        else:
            self.chunk_size = chunk_size

        # Search space tracking
        self.search_space = self.metadata.search_space
        self.cursor = 0
        self.reclaimed_ranges: List[Tuple[int, int]] = []
        self.active_leases: Dict[str, Lease] = {}
        self.completed_hashes = 0
        self.pass_number = 1
        # Range history: (start, end) -> Set of worker_ids that scanned/attempted this chunk
        self.range_history: Dict[Tuple[int, int], set] = {}

        # Workers
        self.workers: Dict[str, WorkerRecord] = {}

        # Solved state
        self.is_solved = False
        self.winning_nonce: Optional[int] = None
        self.solved_by: Optional[str] = None
        self.winner_id: Optional[str] = None
        self.decrypted_file_path: Optional[Path] = None
        self.decrypted_bytes: Optional[bytes] = None

        # WebSockets
        self.connected_sockets: List[WebSocket] = []

    def get_lease(self, worker_id: str, name: str, device: str, cores: int) -> Dict[str, Any]:
        """
        Allocate a range chunk for a worker with device/algo tailored sizing and adaptive timeouts.
        Enforces sabotage defense: avoids re-assigning unverified chunks to the same worker who scanned them.
        """
        now = time.time()
        # Update worker registry
        if worker_id not in self.workers:
            self.workers[worker_id] = WorkerRecord(
                worker_id=worker_id, name=name, device=device, cores=cores, last_seen=now
            )
        else:
            w = self.workers[worker_id]
            w.name = name
            w.device = device
            w.cores = cores
            w.last_seen = now

        if self.metadata.status == "SHREDDED":
            return {
                "status": "shredded",
                "message": "This file is irrevocably crypto-shredded. Decryption is mathematically impossible.",
                "cert_id": self.metadata.cert_id,
            }

        if self.is_solved:
            return {
                "status": "solved",
                "solution": self.winning_nonce,
                "solved_by": self.solved_by,
            }

        # Check for expired leases
        self._reclaim_expired_leases(now)

        is_scrypt = self.metadata.pow_alg == "scrypt"

        # Device-adaptive chunk sizing
        if device in ("browser", "mobile", "web"):
            if is_scrypt:
                alloc_chunk = min(20, self.chunk_size)
            else:
                alloc_chunk = min(500_000, max(100_000, self.chunk_size // 4))
        else:
            alloc_chunk = self.chunk_size

        # 1. Allocate from reclaimed ranges first, preferring ranges worker hasn't scanned yet
        start = None
        end = None
        if self.reclaimed_ranges:
            chosen_idx = None
            for idx, r in enumerate(self.reclaimed_ranges):
                if worker_id not in self.range_history.get(r, set()):
                    chosen_idx = idx
                    break
            if chosen_idx is not None:
                start, end = self.reclaimed_ranges.pop(chosen_idx)
            elif not (self.cursor < self.search_space):
                # Fallback: pop first if no cursor space left
                start, end = self.reclaimed_ranges.pop(0)

        # 2. Allocate fresh chunk from search space
        if start is None:
            if self.cursor < self.search_space:
                start = self.cursor
                end = min(self.cursor + alloc_chunk, self.search_space)
                self.cursor = end
            else:
                # If all ranges were processed but no solution was found (e.g. lying workers),
                # trigger a second verification pass over the space with reset completed_hashes!
                if not self.active_leases and not self.is_solved:
                    self.cursor = 0
                    self.pass_number += 1
                    self.completed_hashes = 0
                    start = 0
                    end = min(alloc_chunk, self.search_space)
                    self.cursor = end
                else:
                    return {"status": "waiting", "message": "All ranges currently leased"}

        # In second or later pass: ensure saboteur cannot re-claim the exact range they falsely marked done
        if self.pass_number > 1:
            while (start, end) and worker_id in self.range_history.get((start, end), set()) and self.cursor < self.search_space:
                start = self.cursor
                end = min(self.cursor + alloc_chunk, self.search_space)
                self.cursor = end

        chunk_hashes = end - start
        # Adaptive lease timeout
        min_speed = 10.0 if is_scrypt else 100_000.0
        estimated_speed = max(self.workers[worker_id].hashrate, min_speed)
        lease_duration = max(180.0, (chunk_hashes / estimated_speed) * 3.5)

        lease_id = str(uuid.uuid4())[:8]
        self.active_leases[lease_id] = Lease(
            lease_id=lease_id,
            start=start,
            end=end,
            worker_id=worker_id,
            created_at=now,
            expires_at=now + lease_duration,
        )

        return {
            "status": "work",
            "lease_id": lease_id,
            "start": start,
            "end": end,
            "salt": self.metadata.salt.hex(),
            "target_hash": self.metadata.target_hash.hex(),
            "pow_alg": self.metadata.pow_alg,
        }

    def _reclaim_expired_leases(self, now: float):
        expired = [lid for lid, l in self.active_leases.items() if l.expires_at < now]
        for lid in expired:
            lease = self.active_leases.pop(lid)
            self.reclaimed_ranges.append((lease.start, lease.end))

    def record_progress(
        self,
        worker_id: str,
        lease_id: Optional[str],
        hashes_done: int,
        hashrate: float,
        name: Optional[str] = None,
    ) -> bool:
        """
        Record worker progress and close lease.
        Enforces sabotage defense: verifies lease.worker_id == worker_id.
        """
        now = time.time()
        if worker_id in self.workers:
            w = self.workers[worker_id]
            w.hashrate = hashrate
            w.total_hashes += hashes_done
            w.last_seen = now
            if name:
                w.name = name

        if lease_id:
            if lease_id not in self.active_leases:
                return False
            lease = self.active_leases[lease_id]
            # Verify lease ownership to prevent unauthorized closure or sabotage
            if lease.worker_id != worker_id:
                return False
            self.active_leases.pop(lease_id)
            self.completed_hashes += lease.end - lease.start
            self.range_history.setdefault((lease.start, lease.end), set()).add(worker_id)
            return True
        return True

    def submit_solution(self, worker_id: str, nonce: int, name: Optional[str] = None) -> bool:
        """
        Verify candidate solution, decrypt file, and update pool state.
        Security characteristics:
        - ALWAYS verifies nonce first.
        - Unpacks container BEFORE transitioning to solved state.
        """
        # 1. ALWAYS verify nonce first!
        if not verify_nonce(self.metadata.salt, self.metadata.target_hash, nonce, algo=self.metadata.pow_alg):
            return False

        # 2. If already solved, return True if matching winning nonce
        if self.is_solved:
            return nonce == self.winning_nonce

        # 3. Decrypt container FIRST before updating pool state
        try:
            out_file = unpack_container(self.container_path, self.output_path, nonce)
            decrypted_bytes = out_file.read_bytes()
        except Exception:
            return False

        # 4. State transition only on confirmed decryption
        self.is_solved = True
        self.winning_nonce = nonce
        self.solved_by = name or worker_id
        self.winner_id = worker_id
        self.decrypted_file_path = out_file
        self.decrypted_bytes = decrypted_bytes

        return True

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        active_workers_list = []
        total_pool_hashrate = 0.0

        for w in list(self.workers.values()):
            if now - w.last_seen < 30.0:
                # Do NOT leak raw internal worker_id in public stats!
                anonymized_id = hashlib.sha256(w.worker_id.encode()).hexdigest()[:8]
                active_workers_list.append(
                    {
                        "id": anonymized_id,
                        "name": w.name,
                        "device": w.device,
                        "hashrate": w.hashrate,
                        "hashes": w.total_hashes,
                    }
                )
                total_pool_hashrate += w.hashrate

        pct = (self.completed_hashes / self.search_space) * 100.0 if self.search_space > 0 else 0.0

        return {
            "is_solved": self.is_solved,
            "solution": self.winning_nonce,
            "solved_by": self.solved_by,
            "search_space": self.search_space,
            "completed_hashes": min(self.completed_hashes, self.search_space),
            "progress_percent": min(100.0, pct),
            "pool_hashrate": total_pool_hashrate,
            "active_workers": active_workers_list,
        }


def create_pool_app(coordinator: PoolCoordinator) -> FastAPI:
    app = FastAPI(title="LastWord Lock Mining Pool")

    web_dir = Path(__file__).parent / "web"
    if web_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def get_index():
        index_file = web_dir / "index.html"
        if index_file.is_file():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>LastWord Lock Pool Server is Running</h1><p>Web UI folder not mounted.</p>")

    @app.get("/api/info")
    async def get_info():
        return {
            "filename": coordinator.metadata.original_filename,
            "file_size": coordinator.metadata.file_size,
            "status": coordinator.metadata.status,
            "cipher": coordinator.metadata.cipher,
            "cert_id": coordinator.metadata.cert_id,
            "shredded_at": coordinator.metadata.shredded_at,
            "original_sha256": coordinator.metadata.file_sha256,
            "difficulty": coordinator.metadata.difficulty,
            "search_space": coordinator.metadata.search_space,
            "salt": coordinator.metadata.salt.hex(),
            "target_hash": coordinator.metadata.target_hash.hex(),
            "pow_alg": coordinator.metadata.pow_alg,
            "chunk_size": coordinator.chunk_size,
            "is_solved": coordinator.is_solved,
            "solution": coordinator.winning_nonce if coordinator.is_solved else None,
            "solved_by": coordinator.solved_by,
        }

    @app.get("/api/job")
    async def get_job(
        worker_id: str,
        name: str = "Anonymous",
        device: str = "cli",
        cores: int = 1,
    ):
        return coordinator.get_lease(worker_id, name, device, cores)

    client_attempts: Dict[str, List[float]] = {}

    def check_rate_limit(request: Request, max_reqs: int = 5, window_sec: float = 5.0):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        timestamps = client_attempts.setdefault(client_ip, [])
        timestamps[:] = [t for t in timestamps if now - t < window_sec]
        if len(timestamps) >= max_reqs:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: maximum {max_reqs} requests per {int(window_sec)}s. Please slow down."
            )
        timestamps.append(now)

    @app.post("/api/progress")
    async def post_progress(report: ProgressReport):
        ok = coordinator.record_progress(
            worker_id=report.worker_id,
            lease_id=report.lease_id,
            hashes_done=report.hashes_done,
            hashrate=report.hashrate,
            name=report.name,
        )
        if not ok and report.lease_id:
            raise HTTPException(status_code=403, detail="Invalid lease or lease owner mismatch")
        return {"status": "ok"}

    @app.post("/api/submit")
    async def post_submit(solution: SolutionSubmit, request: Request):
        check_rate_limit(request, max_reqs=5, window_sec=5.0)
        # Offload CPU-heavy verify_nonce and decryption to threadpool
        success = await run_in_threadpool(
            coordinator.submit_solution,
            worker_id=solution.worker_id,
            nonce=solution.nonce,
            name=solution.name,
        )
        if not success:
            raise HTTPException(status_code=400, detail="Invalid nonce candidate or puzzle already solved")

        stats = coordinator.get_stats()
        for ws in coordinator.connected_sockets:
            try:
                await ws.send_json(stats)
            except Exception:
                pass

        return {
            "status": "ok",
            "message": "Solution verified! File decrypted.",
            "solution": coordinator.winning_nonce,
            "output_path": str(coordinator.decrypted_file_path),
        }

    @app.get("/api/stats")
    async def get_stats():
        return coordinator.get_stats()

    @app.get("/api/download")
    async def download_file():
        if not coordinator.is_solved or coordinator.decrypted_file_path is None:
            raise HTTPException(status_code=404, detail="File is not yet unlocked.")

        safe_name = Path(coordinator.metadata.original_filename).name or "unlocked_file"
        return FileResponse(
            path=str(coordinator.decrypted_file_path),
            filename=safe_name,
            media_type="application/octet-stream",
        )

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        coordinator.connected_sockets.append(websocket)
        try:
            while True:
                stats = coordinator.get_stats()
                await websocket.send_json(stats)
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            if websocket in coordinator.connected_sockets:
                coordinator.connected_sockets.remove(websocket)
        except Exception:
            if websocket in coordinator.connected_sockets:
                coordinator.connected_sockets.remove(websocket)

    return app
