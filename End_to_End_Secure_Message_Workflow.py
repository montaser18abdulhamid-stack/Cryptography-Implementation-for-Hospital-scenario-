from cryptography.hazmat.primitives.asymmetric import dh, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import hashlib
import base64
import secrets
import time

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

PRIVATE_KEY_FILE = "your_private_key.pem"
PUBLIC_KEY_FILE  = "Your_public_key.pem"

set_time = 120
nonce_checker = set()

with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open(PUBLIC_KEY_FILE, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

def sha256_hash(sender_id, timestamp, msg_nonce, plaintext):
    data = (
        sender_id.encode()
        + b"|"
        + str(timestamp).encode()
        + b"|"
        + msg_nonce
        + b"|"
        + plaintext.encode()
    )
    return hashlib.sha256(data).digest()

def build_payload(sender_id, timestamp, msg_nonce, plaintext, signature_b64):
    return (
        f"SENDER={sender_id}\n"
        f"TIME={timestamp}\n"
        f"NONCE={base64.b64encode(msg_nonce).decode()}\n"
        f"MSG={plaintext}\n"
        f"SIG={signature_b64}\n"
    )

def parse_payload(payload):
    out = {}
    for line in payload.splitlines():
        k, v = line.split("=", 1)
        out[k] = v
    return out

def aes_ctr_encrypt(key, data):
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return nonce, enc.update(data) + enc.finalize()

def aes_ctr_decrypt(key, nonce, ct):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

print("\n Diffie–Hellman Key Exchange ")

parameters = dh.generate_parameters(generator=2, key_size=2048)

param_nums = parameters.parameter_numbers()
print("DH parameter q (prime) =", param_nums.p)
print("DH parameter α (generator) =", param_nums.g)

doctor_private = parameters.generate_private_key()
patient_private = parameters.generate_private_key()

doctor_public = doctor_private.public_key()
patient_public = patient_private.public_key()

doctor_y = doctor_public.public_numbers().y
patient_y = patient_public.public_numbers().y
print("Doctor DH public value (y) =", doctor_y)
print("Patient DH public value (y) =", patient_y)

doctor_shared = doctor_private.exchange(patient_public)
patient_shared = patient_private.exchange(doctor_public)

print("Shared secret equal:", doctor_shared == patient_shared)

digest = hashes.Hash(hashes.SHA256())
digest.update(doctor_shared)
aes_key = digest.finalize()

digest2 = hashes.Hash(hashes.SHA256())
digest2.update(patient_shared)
aes_key_patient = digest2.finalize()

print("AES Session Key (Base64):")
print(base64.b64encode(aes_key).decode())
print("Patient derived same key:", aes_key == aes_key_patient)

print("\n Sender creates signed encrypted message ")

sender_id = "Clinic-Doctor-01"
timestamp = int(time.time())
msg_nonce = secrets.token_bytes(16)

print("Timestamp =", timestamp)
print("Message nonce (Base64) =", base64.b64encode(msg_nonce).decode())

hash_bytes = sha256_hash(sender_id, timestamp, msg_nonce, MED_INFO)

signature = private_key.sign(
    hash_bytes,
    padding.PKCS1v15(),
    utils.Prehashed(hashes.SHA256())
)

signature_b64 = base64.b64encode(signature).decode()

payload_text = build_payload(
    sender_id,
    timestamp,
    msg_nonce,
    MED_INFO,
    signature_b64
)

payload_bytes = payload_text.encode()

nonce_ctr, ciphertext = aes_ctr_encrypt(
    aes_key,
    payload_bytes
)

print("AES-CTR nonce (Base64):")
print(base64.b64encode(nonce_ctr).decode())

print("Ciphertext (Base64):")
print(base64.b64encode(ciphertext).decode())

print("\n Receiver decrypts and verifies :")

decrypted = aes_ctr_decrypt(
    aes_key_patient,
    nonce_ctr,
    ciphertext
).decode()

parsed = parse_payload(decrypted)

recv_time = int(parsed["TIME"])
get_nonce = base64.b64decode(parsed["NONCE"])
recv_msg = parsed["MSG"]
recv_sig = base64.b64decode(parsed["SIG"])

current_time = int(time.time())

if recv_time < current_time - set_time or recv_time > current_time + set_time:
    print("REJECTED: Timestamp invalid")
    exit()

if get_nonce in nonce_checker:
    print("REJECTED: Replay detected")
    exit()

nonce_checker.add(get_nonce)

recomputed_hash = sha256_hash(
    parsed["SENDER"],
    recv_time,
    get_nonce,
    recv_msg
)

public_key.verify(
    recv_sig,
    recomputed_hash,
    padding.PKCS1v15(),
    utils.Prehashed(hashes.SHA256())
)

print("ACCEPTED: Message verified")
print("Decrypted message:")
print(recv_msg)

print("\n=== Step 4: Tampering Test ===")

tamper_index = payload_bytes.find(b"Diagnosis")
if tamper_index == -1:
    tamper_index = 10

tampered = bytearray(ciphertext)
tampered[tamper_index] ^= 0x01
tampered = bytes(tampered)

print("Tampered byte index =", tamper_index)
print("Attempting to verify tampered ciphertext...")

bad_plain = aes_ctr_decrypt(aes_key_patient, nonce_ctr, tampered).decode()
bad_parsed = parse_payload(bad_plain)

bad_hash = sha256_hash(
    bad_parsed["SENDER"],
    int(bad_parsed["TIME"]),
    base64.b64decode(bad_parsed["NONCE"]),
    bad_parsed["MSG"]
)

public_key.verify(
    base64.b64decode(bad_parsed["SIG"]),
    bad_hash,
    padding.PKCS1v15(),
    utils.Prehashed(hashes.SHA256())
)