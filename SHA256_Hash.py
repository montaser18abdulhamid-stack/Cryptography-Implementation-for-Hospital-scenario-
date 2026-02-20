import hashlib

MED_INFO = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

def sha256_hashing(message):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()

def main():
    
    msgsent = MED_INFO
    produced_hash = sha256_hashing(msgsent)

    print("medical message:")
    print(msgsent)
    print("Message after we do SHA-256 hash in hex:")
    print(produced_hash)

if __name__ == "__main__":
    main()