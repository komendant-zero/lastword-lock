"""
Standard library test suite for LastWord Lock.
Validates encryption, container format, PoW verification, commit-reveal,
sabotage defense, and adaptive range leasing.
"""

import sys
import json
import struct
import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from lastword_lock.container import (
    pack_container,
    unpack_container,
    read_container_metadata,
    MAX_HEADER_SIZE,
)
from lastword_lock.coordinator import PoolCoordinator, create_pool_app
from lastword_lock.crypto import verify_nonce


class TestLastWordLock(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_untrusted_container_headers(self):
        test_file = self.tmp_path / "secret.txt"
        test_file.write_text("Secret Contest Prize Data 12345", encoding="utf-8")
        lwl_file = self.tmp_path / "test.lwl"

        # 1. Pack valid container
        pack_container(test_file, lwl_file, difficulty=8, pow_alg="sha256")
        meta, offset, raw_hdr = read_container_metadata(lwl_file)
        self.assertEqual(meta.difficulty, 8)
        self.assertEqual(meta.search_space, 256)

        # 2. Test oversized header > 64KB
        bad_lwl = self.tmp_path / "bad_header_size.lwl"
        with open(bad_lwl, "wb") as f:
            f.write(b"LWL1")
            f.write(struct.pack(">I", 70000))  # 70 KB > 64 KB limit
            f.write(b"\x00" * 100)
        with self.assertRaises(ValueError) as ctx:
            read_container_metadata(bad_lwl)
        self.assertIn("oversized", str(ctx.exception).lower())

        # 3. Test invalid difficulty in header (>62)
        hdr_dict = meta.to_dict()
        hdr_dict["difficulty"] = 100  # > 62
        bad_diff_bytes = json.dumps(hdr_dict).encode("utf-8")
        bad_diff_file = self.tmp_path / "bad_diff.lwl"
        with open(bad_diff_file, "wb") as f:
            f.write(b"LWL1")
            f.write(struct.pack(">I", len(bad_diff_bytes)))
            f.write(bad_diff_bytes)
            f.write(b"dummy_ciphertext")
        with self.assertRaises(ValueError) as ctx:
            read_container_metadata(bad_diff_file)
        self.assertIn("between 1 and 62", str(ctx.exception))

    def test_coordinator_commit_reveal_and_sabotage(self):
        test_file = self.tmp_path / "prize.txt"
        test_file.write_text("Exclusive Prize Winner File", encoding="utf-8")
        lwl_file = self.tmp_path / "contest.lwl"
        pack_container(test_file, lwl_file, difficulty=8, pow_alg="sha256")

        meta, _, _ = read_container_metadata(lwl_file)
        winning_nonce = None
        for n in range(meta.search_space):
            if verify_nonce(meta.salt, meta.target_hash, n, algo="sha256"):
                winning_nonce = n
                break
        self.assertIsNotNone(winning_nonce)

        coordinator = PoolCoordinator(lwl_file, contest_mode=True, chunk_size=50)
        app = create_pool_app(coordinator)
        client = TestClient(app)

        # 1. Lease & Sabotage Check
        job1 = client.get("/api/job?worker_id=honest_1&name=HonestWorker").json()
        self.assertEqual(job1["status"], "work")
        l1_id = job1["lease_id"]

        # Saboteur tries to report progress on honest_1's lease
        sab_res = client.post(
            "/api/progress",
            json={
                "worker_id": "saboteur_99",
                "lease_id": l1_id,
                "hashes_done": 50,
                "hashrate": 1000.0,
            },
        )
        self.assertEqual(sab_res.status_code, 403)

        # Honest worker reports progress
        hon_res = client.post(
            "/api/progress",
            json={
                "worker_id": "honest_1",
                "lease_id": l1_id,
                "hashes_done": 50,
                "hashrate": 1000.0,
            },
        )
        self.assertEqual(hon_res.status_code, 200)

        # 2. Commit-Reveal in contest mode
        worker_winner = "winner_device"
        commit_hash = hashlib.sha256(f"{winning_nonce}:{worker_winner}".encode()).hexdigest()

        # Pre-commit
        c_res = client.post(
            "/api/commit",
            json={"worker_id": worker_winner, "commit": commit_hash},
        )
        self.assertEqual(c_res.status_code, 200)

        # Submit reveal
        sub_res = client.post(
            "/api/submit",
            json={
                "worker_id": worker_winner,
                "name": "LuckyWinner",
                "nonce": winning_nonce,
            },
        )
        self.assertEqual(sub_res.status_code, 200)
        claim_token = sub_res.json()["claim_token"]
        self.assertIsNotNone(claim_token)

        # Eavesdropper tries to steal prize after seeing reveal
        eve_res = client.post(
            "/api/submit",
            json={
                "worker_id": "eve_eavesdropper",
                "name": "Eve",
                "nonce": winning_nonce,
            },
        )
        self.assertEqual(eve_res.status_code, 400)

        # Privacy verification in contest mode
        info = client.get("/api/info").json()
        self.assertTrue(info["is_solved"])
        self.assertIsNone(info["solution"])
        stats = client.get("/api/stats").json()
        self.assertIsNone(stats["solution"])

        # Download authorization
        dl_fail = client.get("/api/download", headers={"X-Claim-Token": "invalid_token"})
        self.assertEqual(dl_fail.status_code, 403)
        dl_success = client.get("/api/download", headers={"X-Claim-Token": claim_token})
        self.assertEqual(dl_success.status_code, 200)
        self.assertEqual(dl_success.content, b"Exclusive Prize Winner File")

    def test_second_pass_reset(self):
        test_file = self.tmp_path / "data.txt"
        test_file.write_text("Hello World", encoding="utf-8")
        lwl_file = self.tmp_path / "pass.lwl"
        pack_container(test_file, lwl_file, difficulty=6, pow_alg="sha256")  # 64 nonces

        coordinator = PoolCoordinator(lwl_file, contest_mode=True, chunk_size=32)
        app = create_pool_app(coordinator)
        client = TestClient(app)

        # Worker 1 scans 0-32
        j1 = client.get("/api/job?worker_id=w1").json()
        client.post("/api/progress", json={"worker_id": "w1", "lease_id": j1["lease_id"], "hashes_done": 32})

        # Worker 2 scans 32-64 (without solution)
        j2 = client.get("/api/job?worker_id=w2").json()
        client.post("/api/progress", json={"worker_id": "w2", "lease_id": j2["lease_id"], "hashes_done": 32})

        # Next job triggers pass 2
        j3 = client.get("/api/job?worker_id=w2").json()
        self.assertEqual(j3["status"], "work")
        self.assertEqual(coordinator.pass_number, 2)
        self.assertEqual(coordinator.completed_hashes, 0)


if __name__ == "__main__":
    unittest.main()
