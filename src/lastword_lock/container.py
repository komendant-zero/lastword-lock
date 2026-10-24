"""
Container management for .lwl (LastWord Lock) encrypted files.
Supports:
- Version 2: Irreversible Crypto-Shredder (Digital Black Hole) with 512-bit AEAD Cascade
- Version 1: Legacy PoW container format
- Strict header bounds validation, path traversal sanitization, and cryptographic AAD authentication
"""

import os
import json
import struct
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass

from .crypto import (
    crypto_shred_payload,
    forensic_wipe_file,
    IrreversibleCryptographicShredError,
    create_puzzle,
    verify_nonce,
    derive_key_from_nonce,
    encrypt_payload,
    wrap_file_key,
    unwrap_file_key,
    decrypt_payload,
)

MAGIC_BYTES_V1 = b"LWL1"
MAGIC_BYTES_V2 = b"LWL2"
MAGIC_BYTES = MAGIC_BYTES_V2
VERSION_V1 = 1
VERSION_V2 = 2
VERSION = VERSION_V2
MAX_HEADER_SIZE = 64 * 1024  # 64 KB maximum header size limit


@dataclass
class ContainerMetadata:
    version: int
    original_filename: str
    file_size: int
    file_sha256: str
    status: str = "SHREDDED"  # "SHREDDED" (irreversible) or "ACTIVE" (legacy PoW)
    cipher: str = "AES-256-GCM + ChaCha20-Poly1305 Cascade"
    key_destruction: str = "ZEROIZED_IN_RAM_512BIT"
    cert_id: str = ""
    shredded_at: str = ""
    iv_aes: bytes = b""
    nonce_chacha: bytes = b""
    # Legacy fields
    difficulty: int = 0
    search_space: int = 0
    salt: bytes = b""
    target_hash: bytes = b""
    key_iv: bytes = b""
    encrypted_key: bytes = b""
    file_iv: bytes = b""
    created_at: str = ""
    pow_alg: str = "sha256"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContainerMetadata":
        version = int(data.get("version", 0))
        if version not in (VERSION_V1, VERSION_V2):
            raise ValueError(f"Unsupported container version {version} (expected {VERSION_V1} or {VERSION_V2})")

        file_size = int(data["file_size"])
        if file_size < 0:
            raise ValueError(f"Invalid file_size {file_size}: cannot be negative.")

        raw_name = str(data.get("original_filename", "unlocked_file"))
        safe_name = Path(raw_name).name or "unlocked_file"

        # Version 2: Irreversible Crypto-Shredded Container
        if version == VERSION_V2 or data.get("status") == "SHREDDED":
            iv_aes = bytes.fromhex(data["iv_aes"]) if "iv_aes" in data else b""
            nonce_chacha = bytes.fromhex(data["nonce_chacha"]) if "nonce_chacha" in data else b""

            return cls(
                version=version,
                original_filename=safe_name,
                file_size=file_size,
                file_sha256=str(data["file_sha256"]),
                status=str(data.get("status", "SHREDDED")),
                cipher=str(data.get("cipher", "AES-256-GCM + ChaCha20-Poly1305 Cascade")),
                key_destruction=str(data.get("key_destruction", "ZEROIZED_IN_RAM_512BIT")),
                cert_id=str(data.get("cert_id", "")),
                shredded_at=str(data.get("shredded_at", "")),
                iv_aes=iv_aes,
                nonce_chacha=nonce_chacha,
            )

        # Version 1: Legacy PoW Container
        difficulty = int(data["difficulty"])
        if difficulty < 1 or difficulty > 62:
            raise ValueError(f"Invalid difficulty {difficulty}: must be between 1 and 62 bits.")

        salt = bytes.fromhex(data["salt"])
        if len(salt) != 16:
            raise ValueError(f"Invalid salt length: expected 16 bytes, got {len(salt)}")

        target_hash = bytes.fromhex(data["target_hash"])
        if len(target_hash) != 32:
            raise ValueError(f"Invalid target_hash length: expected 32 bytes, got {len(target_hash)}")

        key_iv = bytes.fromhex(data["key_iv"])
        if len(key_iv) != 12:
            raise ValueError(f"Invalid key_iv length: expected 12 bytes, got {len(key_iv)}")

        file_iv = bytes.fromhex(data["file_iv"])
        if len(file_iv) != 12:
            raise ValueError(f"Invalid file_iv length: expected 12 bytes, got {len(file_iv)}")

        encrypted_key = bytes.fromhex(data["encrypted_key"])
        pow_alg = str(data.get("pow_alg", "sha256")).lower()
        if pow_alg not in ("sha256", "scrypt"):
            raise ValueError(f"Unsupported PoW algorithm '{pow_alg}'")

        computed_search_space = 1 << difficulty

        return cls(
            version=version,
            original_filename=safe_name,
            file_size=file_size,
            file_sha256=str(data["file_sha256"]),
            status="ACTIVE",
            difficulty=difficulty,
            search_space=computed_search_space,
            salt=salt,
            target_hash=target_hash,
            key_iv=key_iv,
            encrypted_key=encrypted_key,
            file_iv=file_iv,
            created_at=str(data.get("created_at", "")),
            pow_alg=pow_alg,
        )

    def to_dict(self) -> Dict[str, Any]:
        if self.version == VERSION_V2 or self.status == "SHREDDED":
            return {
                "version": self.version,
                "status": self.status,
                "cipher": self.cipher,
                "key_destruction": self.key_destruction,
                "original_filename": self.original_filename,
                "file_size": self.file_size,
                "file_sha256": self.file_sha256,
                "cert_id": self.cert_id,
                "shredded_at": self.shredded_at,
                "iv_aes": self.iv_aes.hex(),
                "nonce_chacha": self.nonce_chacha.hex(),
            }

        return {
            "version": self.version,
            "status": self.status,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "difficulty": self.difficulty,
            "search_space": self.search_space,
            "salt": self.salt.hex(),
            "target_hash": self.target_hash.hex(),
            "key_iv": self.key_iv.hex(),
            "encrypted_key": self.encrypted_key.hex(),
            "file_iv": self.file_iv.hex(),
            "created_at": self.created_at,
            "pow_alg": self.pow_alg,
        }


def pack_crypto_shred_container(
    input_file_path: Path,
    output_file_path: Path,
    wipe_source: bool = False,
) -> ContainerMetadata:
    """
    Irreversibly crypto-shreds a file and writes an authentic .lwl container.
    Features:
    - 512-bit AEAD Cascade (ChaCha20-Poly1305 + AES-256-GCM)
    - RAM-level key zeroization with ctypes.memset
    - Associated Authenticated Data (AAD) header binding
    - Multi-pass forensic storage wipe on original file if wipe_source=True
    - Cryptographic Certificate of Destruction (SHA-256 proof)
    """
    input_path = Path(input_file_path)
    output_path = Path(output_file_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Source file not found: {input_path}")

    raw_data = input_path.read_bytes()
    original_size = len(raw_data)
    original_sha256 = hashlib.sha256(raw_data).hexdigest()
    safe_name = Path(input_path.name).name or "unlocked_file"
    shredded_timestamp = datetime.now(timezone.utc).isoformat()

    # Pre-build header for AAD binding
    partial_meta = {
        "version": VERSION_V2,
        "status": "SHREDDED",
        "cipher": "AES-256-GCM + ChaCha20-Poly1305 Cascade",
        "key_destruction": "ZEROIZED_IN_RAM_512BIT",
        "original_filename": safe_name,
        "file_size": original_size,
        "file_sha256": original_sha256,
        "shredded_at": shredded_timestamp,
    }
    aad_bytes = json.dumps(partial_meta, sort_keys=True).encode("utf-8")

    # Encrypt and zeroize keys in RAM
    ciphertext, iv_aes, nonce_chacha, cert_id = crypto_shred_payload(raw_data, associated_data=aad_bytes)

    # Build final metadata
    metadata = ContainerMetadata(
        version=VERSION_V2,
        original_filename=safe_name,
        file_size=original_size,
        file_sha256=original_sha256,
        status="SHREDDED",
        cipher="AES-256-GCM + ChaCha20-Poly1305 Cascade",
        key_destruction="ZEROIZED_IN_RAM_512BIT",
        cert_id=cert_id,
        shredded_at=shredded_timestamp,
        iv_aes=iv_aes,
        nonce_chacha=nonce_chacha,
    )

    header_json = json.dumps(metadata.to_dict(), sort_keys=True).encode("utf-8")
    header_len = len(header_json)

    # Write binary container
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(MAGIC_BYTES_V2)
        f.write(struct.pack(">I", header_len))
        f.write(header_json)
        f.write(ciphertext)

    # Forensically overwrite original plaintext on disk if requested
    if wipe_source:
        forensic_wipe_file(input_path, passes=3)

    return metadata


def pack_container(
    input_file_path: Path,
    output_file_path: Path,
    difficulty: Optional[int] = None,
    pow_alg: str = "sha256",
    wipe_source: bool = False,
) -> ContainerMetadata:
    """
    Main packing entry point.
    If difficulty is None, creates an irrevocable Crypto-Shredded container (v2).
    If difficulty is specified, creates a legacy PoW container (v1) for backward compatibility.
    """
    if difficulty is None:
        return pack_crypto_shred_container(input_file_path, output_file_path, wipe_source=wipe_source)

    # Legacy v1 packing
    input_path = Path(input_file_path)
    output_path = Path(output_file_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Source file not found: {input_path}")

    raw_data = input_path.read_bytes()
    original_size = len(raw_data)
    original_sha256 = hashlib.sha256(raw_data).hexdigest()

    secret_nonce, salt, target_hash = create_puzzle(difficulty, algo=pow_alg)
    master_key = derive_key_from_nonce(salt, secret_nonce)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    file_key = AESGCM.generate_key(bit_length=256)
    key_iv, encrypted_key = wrap_file_key(master_key, file_key)
    file_iv = os.urandom(12)

    search_space = 1 << difficulty
    safe_name = Path(input_path.name).name or "unlocked_file"
    metadata = ContainerMetadata(
        version=VERSION_V1,
        original_filename=safe_name,
        file_size=original_size,
        file_sha256=original_sha256,
        status="ACTIVE",
        difficulty=difficulty,
        search_space=search_space,
        salt=salt,
        target_hash=target_hash,
        key_iv=key_iv,
        encrypted_key=encrypted_key,
        file_iv=file_iv,
        created_at=datetime.now(timezone.utc).isoformat(),
        pow_alg=pow_alg,
    )

    header_json = json.dumps(metadata.to_dict(), sort_keys=True).encode("utf-8")
    header_len = len(header_json)

    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(file_iv, raw_data, header_json)

    with open(output_path, "wb") as f:
        f.write(MAGIC_BYTES_V1)
        f.write(struct.pack(">I", header_len))
        f.write(header_json)
        f.write(ciphertext)

    if wipe_source:
        forensic_wipe_file(input_path, passes=3)

    return metadata


def read_container_metadata(container_path: Path) -> Tuple[ContainerMetadata, int, bytes]:
    """
    Reads and validates metadata from an .lwl container (supports v1 and v2).
    Enforces strict max header size (64KB).
    """
    path = Path(container_path)
    if not path.is_file():
        raise FileNotFoundError(f"Container file not found: {path}")

    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (MAGIC_BYTES_V1, MAGIC_BYTES_V2):
            raise ValueError(f"Invalid file format: expected {MAGIC_BYTES_V1} or {MAGIC_BYTES_V2}, got {magic}")

        header_len_bytes = f.read(4)
        if len(header_len_bytes) < 4:
            raise ValueError("Truncated file header.")

        (header_len,) = struct.unpack(">I", header_len_bytes)
        if header_len <= 0 or header_len > MAX_HEADER_SIZE:
            raise ValueError(
                f"Invalid or oversized container header: {header_len} bytes (limit is {MAX_HEADER_SIZE} bytes)"
            )

        header_data = f.read(header_len)
        if len(header_data) < header_len:
            raise ValueError("Truncated header metadata.")

        payload_offset = f.tell()

    meta_dict = json.loads(header_data.decode("utf-8"))
    metadata = ContainerMetadata.from_dict(meta_dict)
    return metadata, payload_offset, header_data


def unpack_container(
    container_path: Path,
    output_path: Path,
    winning_nonce: Optional[int] = None,
) -> Path:
    """
    Attempts to decrypt a container.
    If the container was crypto-shredded (Version 2 / status SHREDDED),
    raises IrreversibleCryptographicShredError: decryption is mathematically impossible!
    """
    metadata, payload_offset, header_bytes = read_container_metadata(container_path)

    # 1. Check for Irreversible Crypto-Shredding
    if metadata.version == VERSION_V2 or metadata.status == "SHREDDED":
        raise IrreversibleCryptographicShredError(
            f"Container '{Path(container_path).name}' was irrevocably crypto-shredded at {metadata.shredded_at}.\n"
            f"All 512-bit cascade encryption keys were wiped from volatile RAM with zeroes.\n"
            f"Mathematical recovery is impossible (Certificate ID: {metadata.cert_id})."
        )

    # 2. Legacy v1 Unpacking
    if winning_nonce is None:
        raise ValueError("Nonce required to unlock legacy PoW container.")

    if not verify_nonce(metadata.salt, metadata.target_hash, winning_nonce, algo=metadata.pow_alg):
        raise ValueError("Invalid nonce! Hash does not match target puzzle.")

    master_key = derive_key_from_nonce(metadata.salt, winning_nonce)
    file_key = unwrap_file_key(master_key, metadata.key_iv, metadata.encrypted_key)

    with open(container_path, "rb") as f:
        f.seek(payload_offset)
        ciphertext = f.read()

    decrypted_data = decrypt_payload(file_key, metadata.file_iv, ciphertext, associated_data=header_bytes)

    check_sha256 = hashlib.sha256(decrypted_data).hexdigest()
    if check_sha256 != metadata.file_sha256:
        raise ValueError("Integrity check failed! File corrupted.")

    safe_filename = Path(metadata.original_filename).name or "unlocked_file"
    out_file = Path(output_path)
    if out_file.is_dir():
        out_file = out_file / safe_filename
    else:
        out_file.parent.mkdir(parents=True, exist_ok=True)

    out_file.write_bytes(decrypted_data)
    return out_file
