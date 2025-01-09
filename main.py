import serpent
import RSA
import Rabin
import Utilities
import data_table_values
import padding 
import numpy as np
import os

def generate_secret_key(bit_length =256):
    """Generates a random secret key for encryption."""
    if bit_length % 8 != 0:
        raise ValueError("Bit length must be a multiple of 8")

    byte_length = bit_length // 8  # Calculate the number of bytes needed
    random_bytes = os.urandom(byte_length)  # Generate secure random bytes

    hex_key = random_bytes.hex()  # Convert to hexadecimal string
    return hex_key

def encrypt_message(message, secret_key): 
    encrypted_message = ""
    for i in range(0, len(message), 128): 
        block = message[i:i + 128]
        encrypted_message += serpent.encrypt(block, secret_key)

    return encrypted_message

def decrypt_message(message, secret_key): 
    decrypted_message = ""
    for i in range(0, len(message), 128): 
        block = message[i:i + 128]
        decrypted_message += serpent.decrypt(block, secret_key)

    return decrypted_message

def convert_to_bytes(binary_string):
    num_bytes = (len(binary_string) + 7) // 8 
    binary_bytes = int(binary_string, 2).to_bytes(num_bytes, byteorder="big")
    return binary_bytes


def main():
    block_size=128
    seed = "1234567890abcdef1234567890abcdef"

    #Generating keys 

    alice_public_key_rsa, alice_private_key_rsa = RSA.generate_key_pair()
    alice_rabin_p, alice_rabin_q = Rabin.gen_prime_pair(seed)
    alice_rabin_n = alice_rabin_p * alice_rabin_q

    bob_public_key_rsa, bob_private_key_rsa = RSA.generate_key_pair()
    bob_rabin_p, bob_rabin_q = Rabin.gen_prime_pair(seed)

    secret_key = serpent.hexstring2bitstring(generate_secret_key())

    print("Welcome to Secure SMS Exchange System!")

    ############################ALICE################################
    print("Hello Alice!")

    # User input for SMS
    #message = input("Enter the message to send to Bob: ")

    message= "hello my name is adar i live in karmiel and study software engineering"
    print("original message: ", message)

    #add padding to the message to ensure the message is in length of 128 *x bits. 
    binary_message = Utilities.text_to_binary(message)
    messageAfterPadding= padding.padding_encode(binary_message,block_size)

    # Step 1: Encrypt the message using SERPENT
    print("Encrypting message with SERPENT...")

    encrypted_message = encrypt_message(messageAfterPadding, secret_key)
    encrypted_message_hex= serpent.bitstring2hexstring(encrypted_message)
    print("Message encrypted successfully.")

    # Step 2: Securely share the secret key using RSA
    print("Encrypting secret key with RSA...")


    encrypted_key = RSA.encrypt(bob_public_key_rsa , secret_key)
    print("Secret key encrypted successfully.")

    # Step 3: Sign the encrypted message using Rabin Signature
    print("Generating Rabin signature...")
    signature, padding_sig = Rabin.sign(encrypted_message_hex, alice_rabin_p, alice_rabin_q)
    print("Signature generated successfully.")
    print(padding_sig)

    # Display the encrypted message, key, and signature
    print("\nSecure Message Exchange Details:")
    print(f"Encrypted Message: {encrypted_message_hex}")
    # print(f"Encrypted Key: {encrypted_key}")
    print(f"Signature: {signature}")


    #########################BOB######################################

    print("Hello Bob!")
    #Step 4: Verification (for testing purposes)
    print("\nVerifying signature...")
    is_valid = Rabin.verify(encrypted_message_hex, padding_sig, signature, alice_rabin_n)
    if is_valid:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")

    # Step 5: Decrypt the secret key and message
    print("\nDecrypting the secret key...")
    decrypted_key = RSA.decrypt(bob_private_key_rsa , encrypted_key)
    print("Secret key decrypted successfully.")

    print("Decrypting the message...")
    decrypted_message = decrypt_message(encrypted_message, decrypted_key)

    messageAfterPaddingDecode = padding.padding_decode(decrypted_message, block_size)
    print(f"Original Message: {Utilities.binary_to_text(messageAfterPaddingDecode)}")




if __name__ == "__main__":
    main()