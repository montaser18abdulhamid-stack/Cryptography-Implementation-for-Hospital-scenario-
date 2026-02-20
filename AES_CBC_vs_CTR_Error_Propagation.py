from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

ex_key = "00000000000000009999999933333333"
key = bytes.fromhex(ex_key)

plaintext = MED_INFO.encode("utf-8")

tamper_index = 0

print("Message:", MED_INFO)
print("Key (HEX):", ex_key)

iv_random = get_random_bytes(16)
cbc_enc = AES.new(key, AES.MODE_CBC, iv_random)
cbc_ct = cbc_enc.encrypt(pad(plaintext, 16))

cbc_ct_changed = bytearray(cbc_ct)
old_cbc = cbc_ct_changed[tamper_index]
cbc_ct_changed[tamper_index] ^= 0x01 # change the last bit
new_cbc = cbc_ct_changed[tamper_index]
cbc_ct_changed = bytes(cbc_ct_changed)

cbc_dec = AES.new(key, AES.MODE_CBC, iv_random)
cbc_pt_ok = unpad(cbc_dec.decrypt(cbc_ct), 16)

cbc_dec2 = AES.new(key, AES.MODE_CBC, iv_random)
cbc_pt_mod = unpad(cbc_dec2.decrypt(cbc_ct_changed), 16)

print("\n CBC: ")
print("random iv in HEX):", iv_random.hex().upper())
print("Ciphertext in HEX:", cbc_ct.hex().upper())
print("Tampered byte index:", tamper_index, "byte:", f"{old_cbc:02X} -> {new_cbc:02X}")
print("Modified Ciphertext (HEX):", cbc_ct_changed.hex().upper())
print("Decrypted (original):", cbc_pt_ok.decode("utf-8", errors="replace"))
print("Decrypted (modified):", cbc_pt_mod.decode("utf-8", errors="replace"))

nonce = get_random_bytes(8)
ctr_enc = AES.new(key, AES.MODE_CTR, nonce=nonce)
ctr_ct = ctr_enc.encrypt(plaintext)

ctr_ct_changed = bytearray(ctr_ct)
idx = tamper_index if tamper_index < len(ctr_ct_changed) else 0
old_ctr = ctr_ct_changed[idx]
ctr_ct_changed[idx] ^= 0x01
new_ctr = ctr_ct_changed[idx]
ctr_ct_changed = bytes(ctr_ct_changed)

ctr_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)
ctr_pt_ok = ctr_dec.decrypt(ctr_ct)

ctr_dec2 = AES.new(key, AES.MODE_CTR, nonce=nonce)
ctr_pt_mod = ctr_dec2.decrypt(ctr_ct_changed)

print("\n CTR")
print("Nonce (HEX):", nonce.hex().upper())
print("Ciphertext (HEX):", ctr_ct.hex().upper())
print("Tampered byte index:", idx, "byte:", f"{old_ctr:02X} -> {new_ctr:02X}")
print("Modified Ciphertext (HEX):", ctr_ct_changed.hex().upper())
print("Decrypted (original):", ctr_pt_ok.decode("utf-8", errors="replace"))
print("Decrypted (modified):", ctr_pt_mod.decode("utf-8", errors="replace"))