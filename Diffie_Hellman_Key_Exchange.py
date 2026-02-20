from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
import base64

print("C1: Diffie–Hellman")

paramater_used = dh.generate_parameters(generator=2, key_size=2048)

param_nums = paramater_used.parameter_numbers()
q = param_nums.p
α = param_nums.g

print("\n parameters :")
print("q (prime) =", q)
print("α (generator) =", α)

doctor_prvt = paramater_used.generate_private_key()
doctor_public = doctor_prvt.public_key()

patient_prvt = paramater_used.generate_private_key()
patient_public = patient_prvt.public_key()

public_value_Doctor = doctor_public.public_numbers().y
patient_public_value = patient_public.public_numbers().y

print("\nPublic keys exchanged:")
print("Doctor public value =", public_value_Doctor)
print("Patient public value =", patient_public_value)

doctor_shared = doctor_prvt.exchange(patient_public)
patient_shared = patient_prvt.exchange(doctor_public)

print("\nCheck:")
print(doctor_shared == patient_shared)

hash_1 = hashes.Hash(hashes.SHA256())
hash_1.update(doctor_shared)
doctor_session_key = hash_1.finalize()

hash_2 = hashes.Hash(hashes.SHA256())
hash_2.update(patient_shared)
patient_session_key = hash_2.finalize()

print("\n hashed session key :")
print("Doctor key  in hex =", doctor_session_key.hex().upper())
print("Patient key hex =", patient_session_key.hex().upper())

print("\nSession key:")
print("Doctor key in base64 =", base64.b64encode(doctor_session_key).decode("utf-8"))
print("Patient key in base64 =", base64.b64encode(patient_session_key).decode("utf-8"))

print("\n Is it the same session key?")
print(doctor_session_key == patient_session_key)