from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import base64
MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"
wrong_message = "Patient: Ale Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

prvt_key_infile = "your_private_key.pem"
public_key_infile  = "Your_public_key.pem"

with open(prvt_key_infile, "rb") as file:
    private_key = serialization.load_pem_private_key(file.read(), password=None)

with open(public_key_infile, "rb") as file:
    public_key = serialization.load_pem_public_key(file.read())

hash_hex = hashlib.sha256(MED_INFO.encode("utf-8")).hexdigest().upper()

digital_signature = private_key.sign( # digital signature signing through the sender private key.
    MED_INFO.encode("utf-8"),
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_inbytes = base64.b64encode(digital_signature).decode("utf-8")

print("RSA Signature + Verify (SHA-256) ")
print("\nPlaintext message:")
print(MED_INFO)

print("\nSHA-256 hash in HEX:")
print(hash_hex)

print("\nSignature in Base64:")
print(signature_inbytes)

public_key.verify( # check if verify is the same as sign (should work)
    digital_signature,
    MED_INFO.encode("utf-8"),
    padding.PKCS1v15(),
    hashes.SHA256()
)
print("\n (original message): Passed")

print("\nMessage with 1 character changed:")
print(wrong_message)

print("\n Verification result on wrong message:")
public_key.verify( # check if verify is the same as sign (shouldnt work)
    digital_signature,
    wrong_message.encode("utf-8"),
    padding.PKCS1v15(),
    hashes.SHA256()
)