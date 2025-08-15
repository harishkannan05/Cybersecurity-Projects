"""Text Encryption Tool: AES, DES and RSA"""

import base64
from typing import Tuple
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ---------- AES ----------
def aes_encrypt(plain_text: str, key: bytes) -> Tuple[str, str]:
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    return base64.b64encode(cipher.iv).decode(), base64.b64encode(ct).decode()

def aes_decrypt(iv_b64: str, ct_b64: str, key: bytes) -> str:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")


# ---------- DES ----------
def des_encrypt(plain_text: str, key: bytes) -> Tuple[str, str]:
    cipher = DES.new(key, DES.MODE_CBC)
    ct = cipher.encrypt(pad(plain_text.encode("utf-8"), DES.block_size))
    return base64.b64encode(cipher.iv).decode(), base64.b64encode(ct).decode()

def des_decrypt(iv_b64: str, ct_b64: str, key: bytes) -> str:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode("utf-8")


# ---------- RSA ----------
def generate_rsa_keys() -> Tuple[bytes, bytes]:
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(plain_text: str, public_key_pem: bytes) -> str:
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    ct = cipher.encrypt(plain_text.encode("utf-8"))
    return base64.b64encode(ct).decode()

def rsa_decrypt(ct_b64: str, private_key_pem: bytes) -> str:
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    ct = base64.b64decode(ct_b64)
    return cipher.decrypt(ct).decode("utf-8")


def main() -> None:
    while True:
        print("\n=== Text Encryption Tool ===")
        print("1) AES")
        print("2) DES")
        print("3) RSA")
        print("4) Exit")
        choice = input("Choose your option: ").strip()

        if choice == "1":
            text = input("Enter text to encrypt: ")
            key = get_random_bytes(16)  # AES-128
            iv, ct = aes_encrypt(text, key)
            print(f"\n[AES]")
            print(f"Key (base64): {base64.b64encode(key).decode()}")
            print(f"IV  (base64): {iv}")
            print(f"CT  (base64): {ct}")
            print(f"Decrypted    : {aes_decrypt(iv, ct, key)}")

        elif choice == "2":
            text = input("Enter text to encrypt: ")
            key = get_random_bytes(8)   
            iv, ct = des_encrypt(text, key)
            print(f"\n[DES]")
            print(f"Key (base64): {base64.b64encode(key).decode()}")
            print(f"IV  (base64): {iv}")
            print(f"CT  (base64): {ct}")
            print(f"Decrypted    : {des_decrypt(iv, ct, key)}")

        elif choice == "3":
            text = input("Enter text to encrypt: ")
            priv, pub = generate_rsa_keys()
            ct = rsa_encrypt(text, pub)
            print(f"\n[RSA]")
            print(f"Public Key (PEM):\n{pub.decode()}")
            print(f"\nPrivate Key (PEM):\n{priv.decode()}")
            print(f"\nCT (base64): {ct}")
            print(f"Decrypted  : {rsa_decrypt(ct, priv)}")

        elif choice == "4":
            print("Goodbye!")
            break
    
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
