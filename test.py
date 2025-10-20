import os

import time

import sys

import binascii

import random

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32        # AES-256

NONCE_SIZE = 12      # Recommended nonce length for AES-GCM

TYPING_BASE_DELAY = 0.020  # delay between characters

def generate_key() -> bytes:

    """Generate random AES-256 key."""

    return os.urandom(KEY_SIZE)

def aesgcm_encrypt(key: bytes, plaintext: str) -> str:

    """Encrypt UTF-8 plaintext using AES-GCM and return hex(nonce + ciphertext + tag)."""

    aesgcm = AESGCM(key)

    nonce = os.urandom(NONCE_SIZE)

    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return binascii.hexlify(nonce + ct).decode("ascii")

def aesgcm_decrypt(key: bytes, hex_blob: str) -> str:

    """Decrypt hex-encoded ciphertext back to UTF-8 plaintext."""

    blob = binascii.unhexlify(hex_blob)

    nonce = blob[:NONCE_SIZE]

    ct_tag = blob[NONCE_SIZE:]

    aesgcm = AESGCM(key)

    pt = aesgcm.decrypt(nonce, ct_tag, None)

    return pt.decode("utf-8")

def type_out(text: str, jitter: float = 0.01):

    """Print characters with slight delay for typing effect."""

    for ch in text:

        sys.stdout.write(ch)

        sys.stdout.flush()

        delay = TYPING_BASE_DELAY + random.uniform(-jitter, jitter)

        if delay < 0:

            delay = 0

        time.sleep(delay)

    sys.stdout.write("\n")

    sys.stdout.flush()

def noisy_burst(length: int = 80):

    """Simulate random noise burst like static."""

    chars = "0123456789abcdef!@#$%^&*()_+-=[]{};:,<.>/?|~ "

    s = "".join(random.choice(chars) for _ in range(length))

    type_out(s, jitter=0.03)

def slow_reveal(label: str, payload: str):

    """Reveal payload slowly in chunks like a signal transmission."""

    type_out(f"[{label}] TRANSMISSION BEGIN")

    blocks = [payload[i:i+8] for i in range(0, len(payload), 8)]

    for i, block in enumerate(blocks):

        type_out(block + (" " if (i % 8 != 7) else "\n"), jitter=0.015)

        if i % 16 == 15:

            time.sleep(0.4)

    type_out(f"[{label}] TRANSMISSION END")

def main():

    message_hex = (

"58 69 6e 20 63 68 61 6f 20 63 6f 6e 67 20 64 6f 6e 67 20 61 6e 68 20 65 6d 20 73 61 63 68 2c 20 74 69 6e 68 20 68 6f 61 20 63 75 61 20 66 61 63 65 62 6f 6f 6b 20 56 69 65 74 20 4e 61 6d 2e 20 54 6f 69 20 74 6f 69 20 74 75 20 68 61 6e 68 20 74 69 6e 68 20 4b 65 6c 70 65 72 31 38 78 32 20 78 69 6e 20 67 75 69 20 74 61 6e 67 20 61 6e 68 20 65 6d 20 6d 6f 6e 20 71 75 61 20 71 75 65 20 68 75 6f 6e 67 20 4e 68 61 74 20 42 61 6e 20 4d 4e 4c 2e 20 4e 65 75 20 4e 68 61 74 20 42 61 6e 20 74 68 75 61 20 63 68 75 6e 67 20 74 6f 69 20 73 65 20 74 61 6e 20 63 6f 6e 67 20 74 72 61 69 20 64 61 74 2e"

    )

    secret_message = bytes.fromhex(message_hex).decode("utf-8")

    key = generate_key()

    key_hex = binascii.hexlify(key).decode("ascii")

    ciphertext_hex = aesgcm_encrypt(key, secret_message)

    type_out("++ Incoming signal locked ++", jitter=0.01)

    noisy_burst(60)

    time.sleep(0.6)

    type_out("Frequency: 137.5 MHz | Modulation: Unknown", jitter=0.01)

    time.sleep(0.4)

    noisy_burst(40)

    time.sleep(0.5)

    slow_reveal("KEPLER-18X2", ciphertext_hex)

    type_out("\n[KEY-HINT] (for advanced decoders only):", jitter=0.01)

    for blk in [key_hex[i:i+8] for i in range(0, len(key_hex), 8)]:

        sys.stdout.write(blk + " ")

        sys.stdout.flush()

        time.sleep(0.07 + random.uniform(0, 0.05))

        if random.random() < 0.2:

            sys.stdout.write(random.choice("~!@#%^&* "))

            sys.stdout.flush()

    sys.stdout.write("\n\n")

    sys.stdout.flush()

    type_out(">>> Local verification (decrypted):", jitter=0.01)

    try:

        recovered = aesgcm_decrypt(key, ciphertext_hex)

        type_out(recovered, jitter=0.005)

    except Exception as e:

        type_out("[Decryption failed: " + str(e) + "]", jitter=0.01)

    type_out("\n++ Transmission ended ++", jitter=0.01)

if __name__ == "__main__":
    main()