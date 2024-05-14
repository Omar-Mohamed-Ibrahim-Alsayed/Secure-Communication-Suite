import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone  
import pytz
import json
import hashlib


class Authenticator:

    @staticmethod
    def _hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def signup(username, password):
        hashed_password = Authenticator._hash_password(password)
        try:
            with open('user_data.json', 'r+') as file:
                try:
                    data = json.load(file)
                except json.decoder.JSONDecodeError:
                    data = {}
        except FileNotFoundError:
            data = {}

        if username in data:
            return False  
        else:
            data[username] = hashed_password
            with open('user_data.json', 'w') as file:
                json.dump(data, file)
            return True  

    @staticmethod
    def signin(username, password):
        hashed_password = Authenticator._hash_password(password)
        with open('user_data.json', 'r') as file:
            data = json.load(file)
        if username in data and data[username] == hashed_password:
            return True
        else:
            return False

    @staticmethod
    def sign(message, private_key):
        padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        return base64.b64encode(private_key.sign(message, padding_instance, hashes.SHA256()))

    @staticmethod
    def verify(message, signature, public_key):
        sig = base64.b64decode(signature)
        padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        try:
            public_key.verify(sig, message, padding_instance, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate_self_signed_certificate(private_key, subject_name, valid_days=365):
        #AMO is the intials of our names
        subject = issuer = cryptography.x509.Name([
            cryptography.x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
            cryptography.x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cairo"),
            cryptography.x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CNS_PROJ"),
            cryptography.x509.NameAttribute(NameOID.COMMON_NAME, "AMO"),
        ])
        cert = cryptography.x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key() 
        ).serial_number(
            cryptography.x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)  
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=2) 
        ).add_extension(
            cryptography.x509.SubjectAlternativeName([cryptography.x509.DNSName("localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        return cert

    @staticmethod
    def verify_certificate(certificate, issuer_public_key):
        try:
            cert = cryptography.x509.load_pem_x509_certificate(certificate, default_backend())

            cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )

            issuer_common_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            expected_issuer_common_name = "AMO"
            if issuer_common_name != expected_issuer_common_name:
                return False

            not_valid_before = cert.not_valid_before_utc
            not_valid_after = cert.not_valid_after_utc

            now = datetime.now(timezone.utc)
            if now < not_valid_before or now > not_valid_after:
                return False

            subject_common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            expected_subject_common_name = "AMO"  
            if subject_common_name != expected_subject_common_name:
                return False

            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )

            return True

        except (ValueError, IndexError, InvalidSignature):
            return False
