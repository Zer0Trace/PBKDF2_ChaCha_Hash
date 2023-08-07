# Import required modules
import hashlib
import struct
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Define the custom hash function class
class CustomHash:
    def __init__(self, password):
        self.block_size = 64  # ChaCha block size
        self.hash_size = 32   # Output hash size in bytes

        # Derive a secure key from the provided password
        salt = get_random_bytes(16)  # Generate a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # Number of iterations for PBKDF2
            salt=salt,
            length=32,  # Length of the derived key
            backend=default_backend()
        )
        key = kdf.derive(password)
        self.key = key

        # Use a consistent, predetermined nonce
        self.nonce = b'\x00' * 12

        self.state = bytearray(self.block_size)  # Initial state

    def update(self, data):
        # Pad the data if necessary
        data_len = len(data)
        padding_len = self.block_size - (data_len % self.block_size)
        padded_data = data + bytes([padding_len] * padding_len)

        # Iterate over blocks and process using ChaCha cipher
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]

            # Update the state using ChaCha cipher with consistent nonce
            cipher = ChaCha20.new(key=self.key, nonce=self.nonce)
            encrypted_block = cipher.encrypt(block)
            self.state = hashlib.sha256(self.state + encrypted_block).digest()

    def digest(self):
        return self.state[:self.hash_size]

# Example usage
if __name__ == "__main__":
    # Get password from the user (you can replace this with your password)
    password = b"mysecretpassword"

    # Initialize the hash function with the provided password
    custom_hash = CustomHash(password)

    # Update the hash function with input data
    input_data = b"Hello, world! This is a test."
    custom_hash.update(input_data)

    # Get the digest (hash) of the input data
    hash_result = custom_hash.digest()

    print("Input Data:", input_data)
    print("Custom Hash:", hash_result.hex())
