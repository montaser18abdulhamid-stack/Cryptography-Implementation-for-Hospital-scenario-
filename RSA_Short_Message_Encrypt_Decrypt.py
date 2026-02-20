from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

Message = "2004"

PRIVATE_KEY_FILE = "your_private_key.pem"
PUBLIC_KEY_FILE  = "Your_public_key.pem"

with open(PRIVATE_KEY_FILE, "rb") as file:
    private_key = serialization.load_pem_private_key(file.read(), password=None)

with open(PUBLIC_KEY_FILE, "rb") as file:
    public_key = serialization.load_pem_public_key(file.read())

encrypt = public_key.encrypt(
    Message.encode("utf-8"),
    padding.PKCS1v15()
)

cipher_b64 = base64.b64encode(encrypt).decode("utf-8")

dec = private_key.decrypt(
    encrypt,
    padding.PKCS1v15()
).decode("utf-8")

print(" RSA Encrypt + Decrypt (PKCS1v15)")

print("\n Medical Message:")
print(Message)

print("\n Medical message in Ciphertext (Base64):")
print(cipher_b64)

print("\n plaintext recovered:")
print(dec)