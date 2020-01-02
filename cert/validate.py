# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# R: Write a program that verifies your certificate 
# (since it is a root certificate, it is sufficient to check 
# whether certificate issuer and subject are the same ...
# -----------------------------------------------------------------------------
# Sertifikāta pārbaude - salīdzina issuer ar subject (self-signed sertifikātam)
# -----------------------------------------------------------------------------
with open("certificate.pem", mode='rb') as file: certificateBytes = file.read()
cert = x509.load_pem_x509_certificate(certificateBytes, default_backend())
issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
subject = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
validity = "valīds" if issuer == subject else "nevalīds"
print(f'Sertifkāta izdevējs {issuer} sertificē {subject}. Self-signed sertifikāts ir {validity}.')

# issuer_public_key = load_pem_public_key(pem_issuer_public_key, default_backend())
# cert_to_check = x509.load_pem_x509_certificate(pem_data_to_check, default_backend())
# issuer_public_key.verify(
#     cert_to_check.signature,
#     cert_to_check.tbs_certificate_bytes,
#     # Depends on the algorithm used to create the certificate
#     padding.PKCS1v15(),
#     cert_to_check.signature_hash_algorithm,
# )