"""
Container management for .lwl (LastWord Lock) encrypted files.
Handles packing, unpacking, metadata parsing, path traversal sanitization,
header bounds validation, and cryptographic AEAD header authentication.
"""

import json
import struct
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
from dataclasses import dataclass

from .crypto import (
    create_puzzle,
    verify_nonce,
    derive_key_from_nonce,
    encrypt_payload,
    wrap_file_key,
    unwrap_file_key,
    decrypt_payload,
)

MAGIC_BYTES = b"LWL1"
VERSION = 1
MAX_HEADER_SIZE = 64 * 1024  # 64 KB maximum header size limit


@dataclass
class ContainerMetadata:
    version: int
    original_filename: str
    file_size: int
    file_sha256: str
    difficulty: int
    search_space: int
    salt: bytes
    target_hash: bytes
    key_iv: bytes
    encrypted_key: bytes
    file_iv: bytes
    created_at: str
    pow_alg: str = "sha256"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContainerMetadata":
        version = int(data.get("version", 0))
        if version != VERSION:
            raise ValueError(f"Unsupported container version {version} (expected {VERSION})")

        difficulty = int(data["difficulty"])
        if difficulty < 1 or difficulty > 62:
            raise ValueError(f"Invalid difficulty {difficulty}: must be between 1 and 62 bits.")

        file_size = int(data["file_size"])
        if file_size < 0:
            raise ValueError(f"Invalid file_size {file_size}: cannot be negative.")

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

        # Never trust search_space from file; compute directly from validated difficulty
        computed_search_space = 1 << difficulty

        # Sanitize original_filename immediately upon parsing
        raw_name = str(data.get("original_filename", "unlocked_file"))
        safe_name = Path(raw_name).name or "unlocked_file"

        return cls(
            version=int(data["version"]),
            original_filename=safe_name,
            file_size=file_size,
            file_sha256=str(data["file_sha256"]),
            difficulty=difficulty,
            search_space=computed_search_space,
            salt=salt,
            target_hash=target_hash,
            key_iv=key_iv,
            encrypted_key=encrypted_key,
            file_iv=file_iv,
            created_at=str(data["created_at"]),
            pow_alg=pow_alg,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
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


def pack_container(
    input_file_path: Path,
    output_file_path: Path,
    difficulty: int,
    pow_alg: str = "sha256",
) -> ContainerMetadata:
    """
    Encrypts a file with an instant PoW mining puzzle and writes the .lwl container.
    Security characteristics:
    - O(1) instant encryption with AES-256-GCM.
    - Header is authenticated via AES-256-GCM AAD to prevent tampering.
    - Note: The creator inherently knows the file content and key during encryption.
      Contest security relies on social trust in the organizer and public wallet address.
    """
    input_path = Path(input_file_path)
    output_path = Path(output_file_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Source file not found: {input_path}")

    raw_data = input_path.read_bytes()
    original_size = len(raw_data)
    original_sha256 = hashlib.sha256(raw_data).hexdigest()

    # 1. Create PoW puzzle
    secret_nonce, salt, target_hash = create_puzzle(difficulty, algo=pow_alg)

    # 2. Derive master key from secret nonce
    master_key = derive_key_from_nonce(salt, secret_nonce)

    # 3. Generate random file key and wrap it with master key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os

    file_key = AESGCM.generate_key(bit_length=256)
    key_iv, encrypted_key = wrap_file_key(master_key, file_key)
    file_iv = os.urandom(12)

    # 4. Build metadata
    search_space = 1 << difficulty
    safe_name = Path(input_path.name).name or "unlocked_file"
    metadata = ContainerMetadata(
        version=VERSION,
        original_filename=safe_name,
        file_size=original_size,
        file_sha256=original_sha256,
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

    # 5. Encrypt payload with AES-GCM using header_json as Associated Authenticated Data (AAD)
    # Any tampering with the header will cause AES-GCM authentication to fail!
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(file_iv, raw_data, header_json)

    # 6. Write binary container
    with open(output_path, "wb") as f:
        f.write(MAGIC_BYTES)
        f.write(struct.pack(">I", header_len))
        f.write(header_json)
        f.write(ciphertext)

    return metadata


def read_container_metadata(container_path: Path) -> Tuple[ContainerMetadata, int, bytes]:
    """
    Reads only the header metadata from an .lwl container.
    Enforces strict max header size (64KB) to prevent memory exhaustion attacks.
    Returns (metadata, payload_offset, raw_header_bytes).
    """
    path = Path(container_path)
    if not path.is_file():
        raise FileNotFoundError(f"Container file not found: {path}")

    with open(path, "rb") as f:
        magic = f.read(len(MAGIC_BYTES))
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid file format: expected {MAGIC_BYTES}, got {magic}")

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
    winning_nonce: int,
) -> Path:
    """
    Verifies the winning nonce, authenticates the header, decrypts the container,
    and writes the original file with path traversal protection.
    Returns path to decrypted file.
    """
    metadata, payload_offset, header_bytes = read_container_metadata(container_path)

    # 1. Verify nonce against target hash
    if not verify_nonce(metadata.salt, metadata.target_hash, winning_nonce, algo=metadata.pow_alg):
        raise ValueError("Invalid nonce! Hash does not match target puzzle.")

    # 2. Derive master key
    master_key = derive_key_from_nonce(metadata.salt, winning_nonce)

    # 3. Unwrap file key
    file_key = unwrap_file_key(master_key, metadata.key_iv, metadata.encrypted_key)

    # 4. Read ciphertext
    with open(container_path, "rb") as f:
        f.seek(payload_offset)
        ciphertext = f.read()

    # 5. Decrypt payload with header_bytes as Associated Authenticated Data (AAD)
    # If any byte in the header was altered, decrypt_payload raises InvalidTag!
    decrypted_data = decrypt_payload(file_key, metadata.file_iv, ciphertext, associated_data=header_bytes)

    # 6. Integrity check
    check_sha256 = hashlib.sha256(decrypted_data).hexdigest()
    if check_sha256 != metadata.file_sha256:
        raise ValueError("Integrity check failed! File corrupted.")

    # 7. Path Traversal Protection
    safe_filename = Path(metadata.original_filename).name
    if not safe_filename or safe_filename in (".", ".."):
        safe_filename = "unlocked_file"

    out_file = Path(output_path)
    if out_file.is_dir():
        out_file = out_file / safe_filename
    else:
        out_file.parent.mkdir(parents=True, exist_ok=True)

    out_file.write_bytes(decrypted_data)
    return out_file
