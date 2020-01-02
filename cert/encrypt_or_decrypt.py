from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

with open("certificate.pem", mode='rb') as file: certificateBytes = file.read()
cert = x509.load_pem_x509_certificate(certificateBytes, default_backend())
print(cert.public_key())

with open("keys.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=bytes("passphrase", "utf-8"),
        backend=default_backend()
    )

# print(private_key)
print(private_key.public_key())
print(private_key.public_key() == cert.public_key())