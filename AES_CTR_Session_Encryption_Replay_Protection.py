from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, time, secrets

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"
set_time = 180
nonce_checker = set()

params = dh.generate_parameters(generator=2, key_size=2048)

doc_priv = params.generate_private_key()
pat_priv = params.generate_private_key()

doc_shared = doc_priv.exchange(pat_priv.public_key())
pat_shared = pat_priv.exchange(doc_priv.public_key())

h = hashes.Hash(hashes.SHA256()); h.update(doc_shared); doc_key = h.finalize()
h = hashes.Hash(hashes.SHA256()); h.update(pat_shared); pat_key = h.finalize()

print("Same session key?", doc_key == pat_key)
KEY = doc_key

def encrypt_ctr(key: bytes, plaintext: str):
    nonce_4_ctr = secrets.token_bytes(16)
    msg_nonce = secrets.token_bytes(16)
    time_stamp = int(time.time())

    enc = Cipher(algorithms.AES(key), modes.CTR(nonce_4_ctr)).encryptor()
    ct = enc.update(plaintext.encode("utf-8")) + enc.finalize()

    return {"time_stamp": time_stamp, "msg_nonce": msg_nonce, "nonce_4_ctr": nonce_4_ctr, "ct": ct}

def decrypt_ctr(key: bytes, p: dict):
    current_time = int(time.time())

    if p["time_stamp"] < current_time - set_time or p["time_stamp"] > current_time + set_time:
        print("REJECT: timestamp outside set time"); return

    if p["msg_nonce"] in nonce_checker:
        print("REJECT: replay (msg nonce was shown before)"); return
    nonce_checker.add(p["msg_nonce"])

    dec = Cipher(algorithms.AES(key), modes.CTR(p["nonce_4_ctr"])).decryptor()
    pt = (dec.update(p["ct"]) + dec.finalize()).decode("utf-8")
    print("ACCEPT:", pt)

payload = encrypt_ctr(KEY, MED_INFO)

print("\nC2 evidence (base64):")
print("AES key    =", base64.b64encode(KEY).decode("utf-8"))
print("CTR nonce  =", base64.b64encode(payload["nonce_4_ctr"]).decode("utf-8"))
print("Msg nonce  =", base64.b64encode(payload["msg_nonce"]).decode("utf-8"))
print("Timestamp  =", payload["time_stamp"])
print("Ciphertext =", base64.b64encode(payload["ct"]).decode("utf-8"))

print("\nRun 1 (valid):")
decrypt_ctr(pat_key, payload)

print("\nRun 2 (replay: nonce+ciphertext):")
decrypt_ctr(pat_key, payload)

print("\nRun 3 (out of window timestamp):")
stale = dict(payload)
stale["time_stamp"] -= 10_000
stale["msg_nonce"] = secrets.token_bytes(16)
decrypt_ctr(pat_key, stale)