import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(secret_passphrase: str, salt: bytes) -> bytes:
    """Derives a standard 32-byte Fernet key from a shared secret passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_passphrase.encode()))


# The salt stays fixed so both sides derive the exact same key from your shared word
SALT = b"shared_github_salt_v1"

if __name__ == "__main__":
    passphrase = input("Enter your shared passphrase: ")
    api_key = input("Enter the raw API key to encrypt: ")

    key = derive_key(passphrase, SALT)
    cipher = Fernet(key)

    encrypted_data = cipher.encrypt(api_key.encode())
    print("\n--- COPY & SEND THIS ENCRYPTED TOKEN ---")
    print(encrypted_data.decode())
