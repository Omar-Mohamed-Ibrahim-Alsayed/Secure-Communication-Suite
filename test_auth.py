from used_models.authentication import Authenticator
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import time
#-------------------------------------------------------Digital Sig tests------------------------------------------

# # Generate a key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )
# public_key = private_key.public_key()

# message = b"Real Key"
# signature = Authenticator.sign(message, private_key)
# assert Authenticator.verify(message, signature, public_key)

# modified_message = b"Fake Key"
# assert not Authenticator.verify(modified_message, signature, public_key)

# print("All tests passed successfully!")

#-------------------------------------------------------Certificate tests------------------------------------------

# from used_models.authentication import Authenticator
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# import os
# from datetime import datetime, timedelta, timezone  # Import timezone separately

# # Generate a private key
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )

# auth = Authenticator()

# # Generate the self-signed certificate
# certificate = auth.generate_self_signed_certificate(private_key, "mysite.com")

# # Specify the full path for the certificate file
# certificate_path = "./certificate.pem"

# # Verify the generated certificate
# verified = auth.verify_certificate(certificate.public_bytes(encoding=serialization.Encoding.PEM), private_key.public_key())

# if verified:
#     print("Certificate verification passed.")
# else:
#     print("Certificate verification failed.")

#-------------------------------------------------------User auth tests------------------------------------------

# # Test a successful signup
# assert Authenticator.signup("user1", "password1")

# # Test signing up with an existing username (should return False)
# assert not Authenticator.signup("user1", "password2")


# # Test signing in with correct credentials
# assert Authenticator.signin("user1", "password1")

# # Test signing in with incorrect password
# assert not Authenticator.signin("user1", "wrongpassword")

# # Test signing in with non-existent username
# assert not Authenticator.signin("nonexistentuser", "password1")

# print("All tests passed successfully!")
import json

with open('user_data.json', 'r') as file:
    data = json.load(file)
    print(data)
