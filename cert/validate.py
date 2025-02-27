from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# R: Write a program that verifies your certificate 
# (since it is a root certificate, it is sufficient to check 
# whether certificate issuer and subject are the same ...
# and whether a digital signature of the issuer matches the subject’s public key
# -----------------------------------------------------------------------------
# Sertifikāta pārbaude - salīdzina issuer ar subject (self-signed sertifikātam)
# -----------------------------------------------------------------------------
with open("certificate.pem", mode='rb') as file: certificateBytes = file.read()
cert = x509.load_pem_x509_certificate(certificateBytes, default_backend())
issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
subject = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
issuerOk = issuer == subject
# -----------------------------------------------------------------------------
# Sertifikāta pārbaude - pārbauda parakstu
# -----------------------------------------------------------------------------
signatureOk = True
with open("keys.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=bytes("pilnigi slepeni", "utf-8"),
        backend=default_backend()
    )
try:
    # divi varianti - izmantojot public key no privātās atslēgas faila 
    # vai nu no paša sertifikāta
    cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    private_key.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
except:
    signatureOk = False

validity = "valīds" if issuerOk and signatureOk else "nevalīds"
print(f'Sertifikāta izdevējs {issuer} sertificē {subject}. Self-signed sertifikāts ir {validity}.')