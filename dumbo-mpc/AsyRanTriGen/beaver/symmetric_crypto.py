from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
from pickle import dumps, loads
import logging


class SymmetricCrypto(object):
    """
    Uses AES with a 32-byte key in GCM mode.
    Semantic security (iv is randomized).
    """

    @staticmethod
    def encrypt(key, plaintext):
        """
        Encrypts the plaintext using AES in GCM mode.
        """
        key = sha256(key).digest()  # hash the key
        assert len(key) == 32
        
        # Generate a random IV (12 bytes is recommended for GCM)
        iv = get_random_bytes(12)

        # Create cipher object
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(dumps(plaintext))

        # Return iv + ciphertext + tag
        return iv + ciphertext + tag

    @staticmethod
    def decrypt(key, ciphertext):
        """
        Decrypts the ciphertext using AES in GCM mode.
        """
        key = sha256(key).digest()  # hash the key
        assert len(key) == 32

        # Extract the iv, ciphertext, and tag
        iv = ciphertext[:12]  # GCM uses 12-byte IV
        tag = ciphertext[-16:]  # GCM tag is 16 bytes
        encrypted_data = ciphertext[12:-16]

        # Create cipher object
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Decrypt and verify the tag
        plaintext = loads(cipher.decrypt_and_verify(encrypted_data, tag))

        return plaintext
