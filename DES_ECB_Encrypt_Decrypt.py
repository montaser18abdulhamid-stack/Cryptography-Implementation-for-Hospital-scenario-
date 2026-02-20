from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"
MED_INFO_bytes = MED_INFO.encode("utf-8")

key_hex = "133457799BBCDFF1"     
key = bytes.fromhex(key_hex)

cipher = DES.new(key, DES.MODE_ECB)

ciphertext = cipher.encrypt(pad(MED_INFO_bytes, 8))
dec = unpad(cipher.decrypt(ciphertext), 8).decode("utf-8")

print("Plaintext in HEX:", MED_INFO_bytes.hex().upper())
print()
print("DES Key in HEX:", key_hex.upper())
print()
print("Ciphertext HEX:", ciphertext.hex().upper())
print()
print("Decryption product in TEXT:", dec)