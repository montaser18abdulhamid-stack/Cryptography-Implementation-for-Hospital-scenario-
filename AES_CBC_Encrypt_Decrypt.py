from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

print("AES Encryption In CBC ")

key_hex = input("Enter AES key in HEX either 32 hex or 64 hex: ").strip().replace(" ", "")
 # ex:00000000000000009999999933333333

key = bytes.fromhex(key_hex)

plaintext_bytes = MED_INFO.encode("utf-8")

random_iv = get_random_bytes(16)
cipher_enc = AES.new(key, AES.MODE_CBC, random_iv)
ciphertext = cipher_enc.encrypt(pad(plaintext_bytes, 16))

cipher_dec = AES.new(key, AES.MODE_CBC, random_iv)
decrypted_bytes = unpad(cipher_dec.decrypt(ciphertext), 16)

print("MEDINFO message:", MED_INFO)
print("AES Key in HEX:", key_hex.upper())
print("IV HEX:", random_iv.hex().upper())
print("Ciphertext in HEX:", ciphertext.hex().upper())
print("Decrypted output:", decrypted_bytes.decode("utf-8"))