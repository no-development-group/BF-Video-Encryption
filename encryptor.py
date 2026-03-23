"""
encryptor.py
------------
Encrypts a video using a daily-rotating key system.
Supports files of any size via chunked AES-GCM encryption.

Usage:
  python encryptor.py <input.mp4> <output.enc>
"""

import sys
import os
import hmac
import hashlib
import secrets
from datetime import date
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 200_000
SALT_SIZE         = 32
NONCE_SIZE        = 12
CHUNK_SIZE        = 256 * 1024 * 1024  # 256 MB — safe under AES-GCM 2 GB limit

def today_utc() -> str:
    d = date.today()
    return f"{d.year}-{d.month:02d}-{d.day:02d}"

def derive_daily_hmac(master_password: str, filename: str, date_str: str) -> bytes:
    key = master_password.encode("utf-8")
    msg = f"{filename}:{date_str}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).digest()

def daily_code_from_hmac(hmac_bytes: bytes) -> str:
    hex8 = hmac_bytes.hex().upper()[:8]
    return hex8[:4] + "-" + hex8[4:]

def derive_aes_key(daily_code: str, date_str: str, salt: bytes) -> bytes:
    password = f"{daily_code}:{date_str}".encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)

def encrypt_file(input_path: str, output_path: str, master_password: str):
    filename    = os.path.basename(output_path)
    date_str    = today_utc()
    salt        = secrets.token_bytes(SALT_SIZE)
    daily_hmac  = derive_daily_hmac(master_password, filename, date_str)
    daily_code  = daily_code_from_hmac(daily_hmac)
    aes_key_raw = derive_aes_key(daily_code, date_str, salt)
    aesgcm      = AESGCM(aes_key_raw)

    print(f"\nDate:       {date_str}")
    print(f"File:       {filename}")
    print(f"Daily code: {daily_code}  <- share this with your viewer today")

    file_size = os.path.getsize(input_path)
    print(f"\nReading {input_path} ({file_size/1024/1024:.0f} MB) ...")

    # Read all chunks first
    chunks = []
    with open(input_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)

    print(f"Encrypting {len(chunks)} chunk(s) ...")

    # File layout: [SALT:32][NUM_CHUNKS:4] then per chunk [NONCE:12][LEN:8][CIPHERTEXT+TAG]
    with open(output_path, "wb") as out:
        out.write(salt)
        out.write(len(chunks).to_bytes(4, "big"))
        for i, chunk in enumerate(chunks):
            nonce      = secrets.token_bytes(NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            out.write(nonce)
            out.write(len(ciphertext).to_bytes(8, "big"))
            out.write(ciphertext)
            print(f"  Chunk {i+1}/{len(chunks)} done")

    out_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"\nDone! -> {output_path} ({out_mb:.0f} MB)")
    print("\nPut video.enc + player.html + launch.bat on the USB.")
    print("Open keygen.html with your master password to see future daily codes.")

def main():
    if len(sys.argv) != 3:
        print("Usage: python encryptor.py <input.mp4> <output.enc>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(input_path):
        print(f"Error: '{input_path}' not found.")
        sys.exit(1)

    print("Master password (keep this secret — never put it on the USB):")
    pw1 = getpass("Password: ")
    pw2 = getpass("Confirm:  ")

    if pw1 != pw2:
        print("Passwords do not match.")
        sys.exit(1)

    encrypt_file(input_path, output_path, pw1)

if __name__ == "__main__":
    main()