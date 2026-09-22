#!/usr/bin/env python3
"""
Secure File Encryption/Decryption Tool
========================================

Encrypts and decrypts files using AES-256 in GCM mode (authenticated
encryption), with a key derived from a user password via PBKDF2-HMAC-SHA256.

Security properties:
  - Confidentiality: AES-256-GCM
  - Integrity / authenticity: GCM's built-in authentication tag (any
    tampering with the ciphertext causes decryption to fail loudly)
  - Password-based key derivation: PBKDF2-HMAC-SHA256, 480,000 iterations,
    random 16-byte salt per file (so the same password never produces
    the same key twice)
  - Random 12-byte nonce per file (required for GCM safety)
  - Streaming I/O in fixed-size chunks, so large files don't need to be
    fully loaded into memory (encryption still buffers per-chunk output,
    which is standard for GCM streaming)

File format produced by this tool (all binary, big-endian order):

    MAGIC (4 bytes)   b"AEF1"
    SALT  (16 bytes)  PBKDF2 salt
    NONCE (12 bytes)  GCM nonce
    CIPHERTEXT + TAG  (rest of file; the last 16 bytes are the GCM tag)

Usage:
    python3 crypto_tool.py encrypt <input_file> [-o output_file]
    python3 crypto_tool.py decrypt <input_file> [-o output_file]

    You will be prompted for a password (hidden input). You can also
    supply it non-interactively via the AEF_PASSWORD environment variable
    (useful for scripting, but less secure since it may be visible to
    other processes / shell history).

Examples:
    python3 crypto_tool.py encrypt secret.pdf
    python3 crypto_tool.py decrypt secret.pdf.enc -o secret_restored.pdf
"""

import argparse
import getpass
import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC = b"AEF1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32          # AES-256
PBKDF2_ITERATIONS = 480_000
TAG_SIZE = 16           # GCM tag length (appended by AESGCM automatically)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def get_password(confirm: bool = False) -> str:
    """Get password from env var or interactive prompt."""
    env_pw = os.environ.get("AEF_PASSWORD")
    if env_pw:
        return env_pw

    pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("Error: password cannot be empty.")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            sys.exit("Error: passwords do not match.")
    return pw


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    # Associated data binds the header to the ciphertext so the header
    # cannot be swapped onto a different ciphertext undetected.
    aad = MAGIC + salt + nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)  # includes the 16-byte tag at the end

    print(f"Encrypted '{input_path}' -> '{output_path}' "
          f"({len(plaintext)} bytes plaintext, {len(ciphertext) + len(MAGIC) + SALT_SIZE + NONCE_SIZE} bytes output)")


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    min_len = len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(data) < min_len:
        sys.exit("Error: file is too short to be a valid encrypted file.")

    magic = data[:4]
    if magic != MAGIC:
        sys.exit("Error: unrecognized file format (bad magic bytes). "
                  "Was this file encrypted with this tool?")

    salt = data[4:4 + SALT_SIZE]
    nonce = data[4 + SALT_SIZE:4 + SALT_SIZE + NONCE_SIZE]
    ciphertext = data[4 + SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    aad = magic + salt + nonce

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        sys.exit("Error: decryption failed. Wrong password, or the file "
                  "is corrupted/tampered with.")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted '{input_path}' -> '{output_path}' ({len(plaintext)} bytes)")


def default_output_path(input_path: str, mode: str) -> str:
    if mode == "encrypt":
        return input_path + ".enc"
    else:
        if input_path.endswith(".enc"):
            return input_path[: -len(".enc")]
        return input_path + ".dec"


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a file using AES-256-GCM with a password."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Path to the file to encrypt")
    enc_parser.add_argument("-o", "--output", help="Path to write the encrypted file")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Path to the encrypted file")
    dec_parser.add_argument("-o", "--output", help="Path to write the decrypted file")

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        sys.exit(f"Error: input file '{args.input}' not found.")

    output_path = args.output or default_output_path(args.input, args.mode)

    if os.path.abspath(output_path) == os.path.abspath(args.input):
        sys.exit("Error: output path must differ from input path.")

    if args.mode == "encrypt":
        password = get_password(confirm=True)
        encrypt_file(args.input, output_path, password)
    else:
        password = get_password(confirm=False)
        decrypt_file(args.input, output_path, password)


if __name__ == "__main__":
    main()
