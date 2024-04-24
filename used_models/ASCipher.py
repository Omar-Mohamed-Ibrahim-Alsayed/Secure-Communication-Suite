from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class RSAKeyExchange(object):
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
    
    def get_public_key(self):
        return self.public_key.export_key()
    
    def encrypt_symmetric_key(self, symmetric_key, recipient_public_key):
        if isinstance(symmetric_key, str):
            symmetric_key = symmetric_key.encode('utf-8')

        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(recipient_public_key))
        encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
        return encrypted_symmetric_key



class ECCKeyExchange(object):
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
    
    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def derive_shared_secret(self, peer_public_key):
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key,
            backend=default_backend()
        )
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key
