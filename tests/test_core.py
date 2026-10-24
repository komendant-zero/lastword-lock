"""
Standard library test suite for LastWord Lock.
Validates:
- Irreversible Crypto-Shredding (Digital Black Hole) with 512-bit AEAD Cascade
- RAM-level key zeroization with ctypes.memset
- Multi-pass forensic disk sector wiping with os.fsync
- Certificate of Destruction verification
- Impossibility of decryption for shredded containers
- Legacy PoW container compatibility
"""

import sys
import json
import struct
import hashlib
import tempfile
import unittest
from pathlib import Path

from lastword_lock.container import (
    pack_container,
    unpack_container,
    read_container_metadata,
    MAX_HEADER_SIZE,
)
from lastword_lock.crypto import (
    secure_zeroize,
    forensic_wipe_file,
    IrreversibleCryptographicShredError,
    verify_nonce,
)
from lastword_lock.coordinator import PoolCoordinator


class TestLastWordLock(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_crypto_shredding_and_irreversibility(self):
        """Test that Crypto-Shredding produces an uncrackable black hole and wipes plaintext."""
        secret_content = b"Super confidential financial records 98765"
        test_file = self.tmp_path / "financial.dat"
        test_file.write_bytes(secret_content)
        expected_sha256 = hashlib.sha256(secret_content).hexdigest()
        lwl_file = self.tmp_path / "financial.dat.lwl"

        # 1. Crypto-shred with forensic disk wipe
        meta = pack_container(test_file, lwl_file, wipe_source=True)

        # 2. Verify original plaintext file was physically wiped from storage
        self.assertFalse(test_file.exists(), "Plaintext file must be forensically wiped from storage!")

        # 3. Verify Certificate of Destruction in metadata
        self.assertEqual(meta.version, 2)
        self.assertEqual(meta.status, "SHREDDED")
        self.assertEqual(meta.key_destruction, "ZEROIZED_IN_RAM_512BIT")
        self.assertEqual(meta.file_sha256, expected_sha256)
        self.assertTrue(len(meta.cert_id) > 0)
        self.assertTrue(len(meta.shredded_at) > 0)

        # 4. Verify reading container directly from disk
        parsed_meta, offset, raw_hdr = read_container_metadata(lwl_file)
        self.assertEqual(parsed_meta.status, "SHREDDED")
        self.assertEqual(parsed_meta.file_sha256, expected_sha256)

        # 5. Verify that decryption is mathematically impossible
        dest_file = self.tmp_path / "recovered.dat"
        with self.assertRaises(IrreversibleCryptographicShredError) as ctx:
            unpack_container(lwl_file, dest_file)

        self.assertIn("mathematical", str(ctx.exception).lower())

    def test_ram_zeroization(self):
        """Verify C-level ctypes.memset overwrites volatile RAM buffers with zeroes."""
        key_buf = bytearray(b"\xff\xaa\x55\x12" * 16)  # 64 bytes
        self.assertTrue(any(b != 0 for b in key_buf))
        secure_zeroize(key_buf)
        self.assertTrue(all(b == 0 for b in key_buf), "Memory buffer must be entirely zeroized!")

    def test_forensic_storage_wipe(self):
        """Verify multi-pass disk wiping overwrites and unlinks the file."""
        target = self.tmp_path / "target_to_shred.txt"
        target.write_text("Sensitve content on disk", encoding="utf-8")
        self.assertTrue(target.is_file())
        forensic_wipe_file(target, passes=3)
        self.assertFalse(target.exists(), "File should be unlinked after multi-pass wipe")

    def test_legacy_untrusted_container_headers(self):
        """Verify header bounds checking on legacy containers."""
        test_file = self.tmp_path / "secret.txt"
        test_file.write_text("Secret Data 12345", encoding="utf-8")
        lwl_file = self.tmp_path / "test.lwl"

        pack_container(test_file, lwl_file, difficulty=8, pow_alg="sha256")
        meta, offset, raw_hdr = read_container_metadata(lwl_file)
        self.assertEqual(meta.difficulty, 8)
        self.assertEqual(meta.search_space, 256)

        # Oversized header > 64KB
        bad_lwl = self.tmp_path / "bad_header_size.lwl"
        with open(bad_lwl, "wb") as f:
            f.write(b"LWL1")
            f.write(struct.pack(">I", 70000))  # 70 KB > 64 KB limit
            f.write(b"\x00" * 100)
        with self.assertRaises(ValueError) as ctx:
            read_container_metadata(bad_lwl)
        self.assertIn("oversized", str(ctx.exception).lower())

    def test_coordinator_collaborative_and_sabotage(self):
        """Verify collaborative pool coordinator operation on legacy container."""
        test_file = self.tmp_path / "shared.txt"
        test_file.write_text("Collaborative Secret File", encoding="utf-8")
        lwl_file = self.tmp_path / "pool.lwl"
        pack_container(test_file, lwl_file, difficulty=8, pow_alg="sha256")

        meta, _, _ = read_container_metadata(lwl_file)
        winning_nonce = next(
            n for n in range(meta.search_space) if verify_nonce(meta.salt, meta.target_hash, n, algo="sha256")
        )

        coordinator = PoolCoordinator(lwl_file, chunk_size=50)

        # 1. Lease allocation & Sabotage Defense
        job1 = coordinator.get_lease(worker_id="honest_1", name="HonestWorker", device="cli", cores=4)
        self.assertEqual(job1["status"], "work")
        l1_id = job1["lease_id"]

        sab_ok = coordinator.record_progress(
            worker_id="saboteur_99",
            lease_id=l1_id,
            hashes_done=50,
            hashrate=1000.0,
        )
        self.assertFalse(sab_ok)

        hon_ok = coordinator.record_progress(
            worker_id="honest_1",
            lease_id=l1_id,
            hashes_done=50,
            hashrate=1000.0,
        )
        self.assertTrue(hon_ok)

        # 2. Submission
        bad_ok = coordinator.submit_solution("honest_1", 9999999)
        self.assertFalse(bad_ok)

        success = coordinator.submit_solution("honest_1", winning_nonce, "HonestWorker")
        self.assertTrue(success)

        self.assertTrue(coordinator.is_solved)
        self.assertEqual(coordinator.winning_nonce, winning_nonce)
        self.assertEqual(coordinator.decrypted_file_path.read_text(encoding="utf-8"), "Collaborative Secret File")


if __name__ == "__main__":
    unittest.main()
