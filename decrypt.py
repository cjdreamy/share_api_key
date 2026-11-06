import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(secret_passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_passphrase.encode()))


SALT = b"shared_github_salt_v1"

if __name__ == "__main__":
    passphrase = input("Enter the agreed shared passphrase: ")
    token = input("Paste the encrypted token: ")

    try:
        key = derive_key(passphrase, SALT)
        cipher = Fernet(key)

        decrypted_data = cipher.decrypt(token.encode())
        print("\n--- DECRYPTED API KEY ---")
        print(decrypted_data.decode())
    except Exception:
        print(
            "\n[Error] Decryption failed! Check that the passphrase or token is correct."
        )
