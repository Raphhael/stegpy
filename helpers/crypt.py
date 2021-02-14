from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from hashlib import sha256
from os import urandom

class Chiffrement:
    """
    - HEADER_SIZE
    - self.header_data
    - encrypt()
    - decrypt()
    """
    HEADER_SIZE = 0
    def __init__(self): self.header_data = None
    def encrypt(self): pass
    def decrypt(self): pass


class AESChiffrement(Chiffrement):
    HEADER_SIZE = 16

    def __init__(self):
        self.header_data = None  # IV

    def encrypt(self, data):
        password = input("Password")
        key = sha256(password.encode()).hexdigest()
        self.header_data = urandom(16)
        cipher = Cipher(AES(key), mode=CBC(self.header_data))
        encryptor = cipher.encryptor()
        return encryptor.update(b"a secret message") + encryptor.finalize()

    def decrypt(self, data):
        password = input("Password")
        key = sha256(password.encode()).hexdigest()
        algorithm = AES(key)
        cipher = Cipher(algorithm, mode=CBC(self.header_data))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

