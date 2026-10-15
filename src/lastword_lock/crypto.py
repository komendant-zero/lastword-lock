"""
Cryptographic core for lastword-lock.
Provides:
- Instantaneous puzzle creation (O(1) time complexity)
- Fast SHA-256 and memory-hard Scrypt candidate verification
- Key derivation via HKDF-SHA256
- AES-256-GCM authenticated encryption and decryption with AAD (associated authenticated data)
"""

import os
import struct
import hashlib
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"lastword-lock:v1"
SALT_SIZE = 16
IV_SIZE = 12
KEY_SIZE = 32  # 256 bits


def compute_pow_hash(salt: bytes, nonce: int, algo: str = "sha256") -> bytes:
    """
    Compute Proof-of-Work hash for a candidate nonce.
    Supports:
    - 'sha256': universal, fast, supported in web browsers & all CPU architectures.
    - 'scrypt': memory-hard (N=16384, r=8, p=1 ~16MB RAM per attempt), heavily GPU/ASIC resistant.
    """
    nonce_bytes = struct.pack(">Q", nonce)
    if algo == "sha256":
        return hashlib.sha256(salt + nonce_bytes).digest()
    elif algo == "scrypt":
        # 16 MB memory-hard scrypt calculation
        return hashlib.scrypt(
            salt + nonce_bytes,
            salt=salt,
            n=16384,
            r=8,
            p=1,
            maxmem=32 * 1024 * 1024,
        )[:32]
    else:
        raise ValueError(f"Unsupported PoW algorithm: '{algo}'")


def create_puzzle(difficulty: int, algo: str = "sha256") -> Tuple[int, bytes, bytes]:
    """
    Generate a mining puzzle with difficulty D.
    Search space is [0, 2^difficulty).
    Returns (secret_nonce, salt, target_hash_bytes).
    Time complexity: O(1) (instantaneous for the encryptor).
    """
    if difficulty < 1 or difficulty > 62:
        raise ValueError("Difficulty must be between 1 and 62 bits.")

    max_nonce = (1 << difficulty) - 1
    secret_nonce = secrets.randbelow(max_nonce + 1)
    salt = os.urandom(SALT_SIZE)

    target_hash = compute_pow_hash(salt, secret_nonce, algo=algo)
    return secret_nonce, salt, target_hash


def verify_nonce(salt: bytes, target_hash: bytes, candidate_nonce: int, algo: str = "sha256") -> bool:
    """
    Verify if a candidate nonce solves the puzzle.
    Time complexity: O(1).
    """
    computed = compute_pow_hash(salt, candidate_nonce, algo=algo)
    return computed == target_hash


def derive_key_from_nonce(salt: bytes, nonce: int) -> bytes:
    """
    Derive 256-bit AES master key from the winning nonce using HKDF-SHA256.
    """
    nonce_bytes = struct.pack(">Q", nonce)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(nonce_bytes)


def encrypt_payload(data: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Generate a random 256-bit file key and encrypt data with AES-256-GCM.
    Cryptographically authenticates associated_data (header) to prevent tampering.
    Returns (file_key, iv, ciphertext_with_tag).
    """
    file_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(file_key)
    iv = os.urandom(IV_SIZE)
    ciphertext = aesgcm.encrypt(iv, data, associated_data)
    return file_key, iv, ciphertext


def wrap_file_key(master_key: bytes, file_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt the file key using the master key derived from the puzzle solution.
    Returns (key_iv, encrypted_key_blob_with_tag).
    """
    aesgcm = AESGCM(master_key)
    iv = os.urandom(IV_SIZE)
    encrypted_key = aesgcm.encrypt(iv, file_key, None)
    return iv, encrypted_key


def unwrap_file_key(master_key: bytes, key_iv: bytes, encrypted_key: bytes) -> bytes:
    """
    Decrypt the file key using the master key.
    """
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(key_iv, encrypted_key, None)


def decrypt_payload(file_key: bytes, iv: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt payload using AES-256-GCM and verify associated_data (header).
    Raises InvalidTag if corrupted, modified header, or incorrect key.
    """
    aesgcm = AESGCM(file_key)
    return aesgcm.decrypt(iv, ciphertext, associated_data)
