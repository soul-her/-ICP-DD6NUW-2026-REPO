import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

SALT_SIZE = 16
KEY_SIZE = 32      # 256-bit key
NONCE_SIZE = 12    # Recommended for AES-GCM
ITERATIONS = 100000


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(filename):
    password = getpass.getpass("Enter password: ").encode()
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_SIZE)

    with open(filename, "rb") as f:
        data = f.read()

    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(filename + ".enc", "wb") as f:
        f.write(salt + nonce + encrypted)

    print("File encrypted successfully.")


def decrypt_file(filename):
    password = getpass.getpass("Enter password: ").encode()

    with open(filename, "rb") as f:
        content = f.read()

    salt = content[:SALT_SIZE]
    nonce = content[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = content[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print("Incorrect password or corrupted file.")
        return

    output_file = filename.replace(".enc", ".dec")
    with open(output_file, "wb") as f:
        f.write(decrypted)

    print("File decrypted successfully.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python file_crypto.py encrypt <filename>")
        print("  python file_crypto.py decrypt <filename>")
        sys.exit(1)

    mode = sys.argv[1]
    file = sys.argv[2]

    if mode == "encrypt":
        encrypt_file(file)
    elif mode == "decrypt":
        decrypt_file(file)
    else:
        print("Invalid option.")
