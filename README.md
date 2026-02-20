# Medsecure Crypto (Python)

A set of educational cryptography scripts demonstrating core building blocks used in a secure messaging scenario:
hashing, symmetric encryption, RSA, Diffie–Hellman key exchange, and an end-to-end workflow.

✅ Code contents were **not modified** — only filenames were made descriptive for GitHub.

## Setup
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

## Scripts
|                        File                            | | What it represents |

| `src/SHA256_Hash.py`                                   | SHA-256 hashing for integrity |
| `src/DES_ECB_Encrypt_Decrypt.py`                       | DES encryption/decryption in ECB mode |
| `src/AES_CBC_Encrypt_Decrypt.py`                       | AES encryption/decryption in CBC mode (IV-based) |
| `src/AES_CBC_vs_CTR_Error_Propagation.py`              | Error propagation comparison: CBC vs CTR after 1-byte tamper |
| `src/RSA_Key_Generation_2048.py`                       | RSA key generation (2048-bit) + PEM export |
| `src/RSA_Signature_SHA256_Sign_Verify.py`              | RSA signature (SHA-256) sign/verify + tamper detection |
| `src/RSA_Short_Message_Encrypt_Decrypt.py`             | RSA encryption/decryption for short messages |
| `src/Diffie_Hellman_Key_Exchange.py`                   | Diffie–Hellman exchange + shared key derivation |
| `src/AES_CTR_Session_Encryption_Replay_Protection.py`  | AES-CTR session encryption + freshness + replay rejection |
| `src/End_to_End_Secure_Message_Workflow.py`            | End-to-end secure message workflow (DH + hash + RSA signature + AES-CTR + freshness) |

## Run
```bash
python src/SHA256_Hash.py
python src/DES_ECB_Encrypt_Decrypt.py
python src/AES_CBC_Encrypt_Decrypt.py
python src/AES_CBC_vs_CTR_Error_Propagation.py
```

### RSA note
Run key generation first:
```bash
python src/RSA_Key_Generation_2048.py
```
It may generate `.pem` files locally — they are ignored by `.gitignore` by default.
