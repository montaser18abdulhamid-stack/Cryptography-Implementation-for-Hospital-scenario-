from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_keys():
    print("=== RSA Key Creation ===")

    priv_path = "your_private_key.pem"
    pub_path = "Your_public_key.pem"

    rsa_private = rsa.generate_private_key(
        public_exponent=65537, # e
        key_size=2048
    )

    pub_bytes = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    priv_bytes = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)

    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    print("Keys saved successfully")
    print("Private key location:", os.path.abspath(priv_path))
    print("Public key location :", os.path.abspath(pub_path))
    print("\nPublic key output:\n")
    print(pub_bytes.decode())

if __name__ == "__main__":
    generate_rsa_keys()