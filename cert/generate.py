# Skripta izmantošanai Python kriptogrāfijas bibliotēka
# `python -m pip install cryptography`

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import json

# Generate our key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
# Write our key to disk for safe keeping
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

# R: the information about the issuer and the subject of the certificate 
# should be read from a text file
with open('issuer_name.json') as f: issuer_deserialized = json.load(f)

subject = issuer = x509.Name([ # subject un issuer ir vienādi
    x509.NameAttribute(NameOID.COUNTRY_NAME, issuer_deserialized["COUNTRY_NAME"]),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, issuer_deserialized["STATE_OR_PROVINCE_NAME"]),
    x509.NameAttribute(NameOID.LOCALITY_NAME, issuer_deserialized["LOCALITY_NAME"]),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_deserialized["ORGANIZATION_NAME"]),
    x509.NameAttribute(NameOID.COMMON_NAME, issuer_deserialized["COMMON_NAME"]),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
# Sign our certificate with our private key
).sign(key, hashes.SHA256(), default_backend())
# Write our certificate out to disk.
with open("certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))