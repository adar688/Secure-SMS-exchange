# Secure SMS Exchange

This project is part of the course **Data Security and Cryptology**. It implements a secure SMS exchange system combining multiple cryptographic techniques to ensure confidentiality, integrity, and authenticity.

---

## **Project Goal**
The goal of this project is to provide:

1. **Confidentiality**: Secure encryption and decryption of SMS messages using the **SERPENT** algorithm.
2. **Secure Key Delivery**: Transmission of the secret encryption key using **RSA** public-key cryptography.
3. **Authenticity**: Verification of the sender and integrity of the message using the **Rabin signature** scheme.

---

## **Features**

- **Encryption & Decryption**:
  - Utilizes the SERPENT block cipher to encrypt and decrypt SMS messages securely.
  - Includes padding to ensure proper block sizes.

- **Secure Key Delivery**:
  - Uses RSA encryption for secure transmission of the symmetric key.

- **Message Authentication**:
  - Implements the Rabin signature scheme to verify the authenticity and integrity of the message.

- **Utilities**:
  - Helper modules for padding, data management, and cryptographic utilities.

---

## **Installation**

### Prerequisites
Ensure you have the following installed on your system:
- **Python 3.7+**
- Required libraries (install via pip):
  ```bash
  pip install -r requirements.txt
  ```

### Repository Setup
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/Secure-SMS-exchange.git
   cd Secure-SMS-exchange
   ```

2. Run the main script to test the implementation:
   ```bash
   python main.py
   ```

---

## **Usage**

### Sending a Secure SMS
1. Prepare your message.
2. Encrypt the message using the SERPENT cipher.
3. Encrypt the symmetric key using RSA and include it in the transmission.
4. Sign the encrypted message using the Rabin signature scheme.

### Receiving a Secure SMS
1. Verify the Rabin signature to ensure message authenticity.
2. Decrypt the symmetric key using RSA.
3. Decrypt the SMS message using the SERPENT cipher.

---

## **Modules**

1. **main.py**: The entry point for the application.
2. **serpent.py**: Implementation of the SERPENT block cipher.
3. **padding.py**: Adds and removes padding to/from messages for block cipher compatibility.
4. **RSA.py**: Provides RSA encryption and decryption functions.
5. **Rabin.py**: Implements the Rabin signature scheme.
6. **data_table_values.py**: Manages constants and lookup tables used in cryptographic operations.
7. **Utilities.py**: Contains helper functions for data handling and formatting.

---

## **Examples**

### Example 1: Encrypting and Sending a Message
```python
from serpent import encrypt
from RSA import rsa_encrypt
from Rabin import sign_message

# Encrypt message
message = "Hello, secure world!"
cipher_text = encrypt(message, secret_key)

# Secure key delivery
encrypted_key = rsa_encrypt(secret_key, recipient_public_key)

# Sign the message
signature = sign_message(cipher_text, sender_private_key)
```

### Example 2: Receiving and Decrypting a Message
```python
from serpent import decrypt
from RSA import rsa_decrypt
from Rabin import verify_signature

# Verify signature
is_valid = verify_signature(cipher_text, signature, sender_public_key)
if not is_valid:
    raise ValueError("Invalid signature")

# Decrypt the key
decrypted_key = rsa_decrypt(encrypted_key, recipient_private_key)

# Decrypt the message
plain_text = decrypt(cipher_text, decrypted_key)
print("Decrypted message:", plain_text)
```

---

## **Contributing**

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

---

## **License**

This project is licensed under the MIT License. See the LICENSE file for details.

---

## **Contact**

For questions or suggestions, feel free to reach out:
- **Email**: Gadazriel7@gmail.com
- **GitHub**: [GadAzriel](https://github.com/GadAzriel)
- **Email**: adar688@gmail.com
- **GitHub**: [AdarBudomski](https://github.com/adar688)
- **Email**: shovalis52txls@gmail.com
- **GitHub**: [ShovalBenShushan](https://github.com/adar688)

Happy coding! 🚀

